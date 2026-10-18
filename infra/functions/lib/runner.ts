import type { ContainerDefinition, RegisterTaskDefinitionCommandInput } from "@aws-sdk/client-ecs";

/**
 * Cloud runner (enterprise `cloudRunner` feature): run a container image on
 * Fargate with a stage's env files, without the plaintext ever passing
 * through this API.
 *
 * Each run is one ECS task with two containers sharing a per-task volume:
 *
 *   enclave-init  our CLI image. Logs in with the task's own IAM role (signed
 *                 sts:GetCallerIdentity; ECS names the role session after the
 *                 task id, which is how the server knows *which* run it is),
 *                 gets a one-time, read-only token for exactly that run's
 *                 project/stage, decrypts in memory, writes /run/secrets, exits.
 *   app           the caller's image, digest-pinned. Starts only if init
 *                 succeeded, mounts /run/secrets read-only, read-only root
 *                 filesystem, non-root, all capabilities dropped.
 *
 * The volume is Fargate ephemeral storage: per task, encrypted by Fargate,
 * destroyed when the task stops. Nothing here is persisted anywhere else.
 *
 * This file is pure (validation + the task definition) so it is testable.
 */

export const INIT = "enclave-init";
export const APP = "app";
export const SECRETS = "/run/secrets";

const DIGEST_IMAGE = /^[a-z0-9][a-z0-9._\-/:]*@sha256:[0-9a-f]{64}$/;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const USER = /^(\d+)(?::(\d+))?$/;
const safeName = (name: string) => /^[\w.@+-]+$/.test(name);

// Docker's default capability set minus CHOWN: what the init container drops.
// It runs as uid 0 only to own the freshly created volume and hand the files
// to the app's uid; Fargate cannot add capabilities, only remove them.
const DEFAULT_CAPS_BUT_CHOWN = [
  "AUDIT_WRITE", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD", "NET_BIND_SERVICE",
  "NET_RAW", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT",
];

// Valid Fargate CPU (units) -> memory (MiB) pairs.
const FARGATE: Record<number, [number, number, number]> = {
  256: [512, 2048, 512],
  512: [1024, 4096, 1024],
  1024: [2048, 8192, 1024],
  2048: [4096, 16384, 1024],
  4096: [8192, 30720, 1024],
};

export interface RunRequest {
  project: string;
  stage: string;
  image: string;
  command: string[];
  files: string[];
  mode: "files" | "env";
  cpu: number;
  memory: number;
  env: Record<string, string>;
  maxMinutes: number;
  user: string;
}

export type Parsed = { ok: true; run: RunRequest } | { ok: false; error: string };

export function parseRunRequest(body: Record<string, unknown>, registries: string[] = []): Parsed {
  const fail = (error: string): Parsed => ({ ok: false, error });
  const { project, stage, image } = body;
  if (typeof project !== "string" || !safeName(project)) return fail("a valid project is required");
  if (typeof stage !== "string" || !safeName(stage)) return fail("a valid stage is required");
  if (typeof image !== "string" || image.length > 512 || !DIGEST_IMAGE.test(image)) {
    return fail("image must be pinned by digest: <registry>/<repo>@sha256:<64 hex>");
  }
  if (registries.length && !registries.some((r) => image.startsWith(r.endsWith("/") ? r : `${r}/`))) {
    return fail(`image registry is not allowed here (allowed: ${registries.join(", ")})`);
  }

  const command = body.command ?? [];
  if (
    !Array.isArray(command) ||
    command.length > 64 ||
    !command.every((c) => typeof c === "string" && c.length <= 1024)
  ) {
    return fail("command must be a list of at most 64 strings");
  }

  const files = body.files ?? [];
  if (!Array.isArray(files) || files.length > 32 || !files.every((f) => typeof f === "string" && safeName(f))) {
    return fail("files must be a list of stored file names");
  }

  const mode = body.mode ?? "files";
  if (mode !== "files" && mode !== "env") return fail("mode must be 'files' or 'env'");
  if (mode === "env" && command.length === 0) {
    return fail("env mode wraps your command in a shell, so a command is required");
  }

  const cpu = body.cpu ?? 256;
  const memory = body.memory ?? 512;
  const range = typeof cpu === "number" ? FARGATE[cpu] : undefined;
  if (!range) return fail(`cpu must be one of ${Object.keys(FARGATE).join(", ")}`);
  if (
    typeof memory !== "number" ||
    memory < range[0] ||
    memory > range[1] ||
    (memory - range[0]) % range[2] !== 0
  ) {
    return fail(`memory for ${cpu} cpu must be ${range[0]}..${range[1]} MiB in steps of ${range[2]}`);
  }

  const env = body.env ?? {};
  if (typeof env !== "object" || env === null || Array.isArray(env)) return fail("env must be an object");
  const entries = Object.entries(env as Record<string, unknown>);
  if (entries.length > 32) return fail("at most 32 env entries");
  for (const [k, v] of entries) {
    if (!ENV_NAME.test(k) || typeof v !== "string" || v.length > 4096) {
      return fail(`env ${k}: expected a valid name and a string value`);
    }
    if (k.startsWith("ENCLAVE_") || k.startsWith("AWS_") || k.startsWith("ECS_")) {
      return fail(`env ${k}: reserved prefix`);
    }
  }

  const maxMinutes = body.maxMinutes ?? 60;
  if (typeof maxMinutes !== "number" || !Number.isInteger(maxMinutes) || maxMinutes < 1 || maxMinutes > 240) {
    return fail("maxMinutes must be an integer between 1 and 240");
  }

  const user = body.user ?? "65534:65534";
  const m = typeof user === "string" ? USER.exec(user) : null;
  if (!m) return fail("user must be numeric uid[:gid]");
  if (m[1] === "0" || m[2] === "0") return fail("the app container may not run as root");

  return {
    ok: true,
    run: {
      project,
      stage,
      image,
      command: command as string[],
      files: files as string[],
      mode,
      cpu: cpu as number,
      memory: memory as number,
      env: env as Record<string, string>,
      maxMinutes,
      user: m[2] ? (user as string) : `${m[1]}:${m[1]}`,
    },
  };
}

export interface Base {
  family: string;
  initImage: string;
  executionRoleArn: string;
  taskRoleArn: string;
  logGroup: string;
  region: string;
  apiUrl: string;
}

export function buildTaskDefinition(run: RunRequest, base: Base): RegisterTaskDefinitionCommandInput {
  const logs = (prefix: string): ContainerDefinition["logConfiguration"] => ({
    logDriver: "awslogs",
    options: { "awslogs-group": base.logGroup, "awslogs-region": base.region, "awslogs-stream-prefix": prefix },
  });

  const init: ContainerDefinition = {
    name: INIT,
    image: base.initImage,
    essential: false,
    user: "0",
    command: ["runner-init", "--dest", SECRETS, "--owner", run.user],
    readonlyRootFilesystem: true,
    environment: [
      { name: "ENCLAVE_API_URL", value: base.apiUrl },
      { name: "AWS_REGION", value: base.region },
      { name: "AWS_DEFAULT_REGION", value: base.region },
    ],
    mountPoints: [
      { sourceVolume: "secrets", containerPath: SECRETS, readOnly: false },
      { sourceVolume: "init-tmp", containerPath: "/tmp", readOnly: false },
    ],
    linuxParameters: { capabilities: { drop: DEFAULT_CAPS_BUT_CHOWN }, initProcessEnabled: true },
    logConfiguration: logs("init"),
  };

  const app: ContainerDefinition = {
    name: APP,
    image: run.image,
    essential: true,
    user: run.user,
    readonlyRootFilesystem: true,
    environment: Object.entries(run.env).map(([name, value]) => ({ name, value })),
    mountPoints: [
      { sourceVolume: "secrets", containerPath: SECRETS, readOnly: true },
      { sourceVolume: "app-tmp", containerPath: "/tmp", readOnly: false },
    ],
    dependsOn: [{ containerName: INIT, condition: "SUCCESS" }],
    linuxParameters: { capabilities: { drop: ["ALL"] }, initProcessEnabled: true },
    stopTimeout: 30,
    logConfiguration: logs("app"),
  };
  if (run.mode === "env") {
    // env.sh is written by runner-init as POSIX `export KEY='value'` lines.
    app.entryPoint = ["/bin/sh", "-c", `. ${SECRETS}/env.sh && exec "$@"`, "enclave-run"];
    app.command = run.command;
  } else if (run.command.length) {
    app.command = run.command;
  }

  return {
    family: base.family,
    requiresCompatibilities: ["FARGATE"],
    networkMode: "awsvpc",
    cpu: String(run.cpu),
    memory: String(run.memory),
    executionRoleArn: base.executionRoleArn,
    taskRoleArn: base.taskRoleArn,
    runtimePlatform: { operatingSystemFamily: "LINUX", cpuArchitecture: "X86_64" },
    volumes: [{ name: "secrets" }, { name: "init-tmp" }, { name: "app-tmp" }],
    containerDefinitions: [init, app],
  };
}

/** ECS task id from a task ARN (…:task/<cluster>/<id>). */
export const taskIdOf = (arn: string) => arn.split("/").at(-1)!;
