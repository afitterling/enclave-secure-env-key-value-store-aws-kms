import { describe, expect, it } from "vitest";
import { buildTaskDefinition, parseRunRequest, taskIdOf, APP, INIT } from "../functions/lib/runner.js";

const IMG = `ghcr.io/acme/api@sha256:${"a".repeat(64)}`;
const ok = (body: Record<string, unknown>, registries?: string[]) => {
  const r = parseRunRequest({ project: "webapp", stage: "prod", image: IMG, ...body }, registries);
  if (!r.ok) throw new Error(r.error);
  return r.run;
};
const err = (body: Record<string, unknown>, registries?: string[]) => {
  const r = parseRunRequest({ project: "webapp", stage: "prod", image: IMG, ...body }, registries);
  return r.ok ? null : r.error;
};
const base = {
  family: "enclave-run-dev",
  initImage: "123.dkr.ecr.eu-central-1.amazonaws.com/init@sha256:" + "b".repeat(64),
  executionRoleArn: "arn:exec",
  taskRoleArn: "arn:task",
  logGroup: "/sst/runner",
  region: "eu-central-1",
  apiUrl: "https://enclavecore.app/api",
};

describe("parseRunRequest", () => {
  it("applies safe defaults", () => {
    expect(ok({})).toMatchObject({ mode: "files", cpu: 256, memory: 512, maxMinutes: 60, user: "65534:65534", command: [] });
  });

  it("requires a digest-pinned image and honours a registry allowlist", () => {
    expect(err({ image: "ghcr.io/acme/api:latest" })).toMatch(/pinned by digest/);
    expect(err({ image: `${IMG} ; rm -rf /` })).toMatch(/pinned/);
    expect(err({}, ["123.dkr.ecr.eu-central-1.amazonaws.com"])).toMatch(/not allowed/);
    expect(ok({}, ["ghcr.io/acme"]).image).toBe(IMG);
    expect(err({}, ["ghcr.io/ac"])).toMatch(/not allowed/); // prefix is a path segment, not a string prefix
  });

  it("refuses root, bad sizes, reserved env and env mode without a command", () => {
    expect(err({ user: "0" })).toMatch(/root/);
    expect(err({ user: "1000:0" })).toMatch(/root/);
    expect(err({ user: "app" })).toMatch(/numeric/);
    expect(err({ cpu: 256, memory: 4096 })).toMatch(/memory/);
    expect(err({ cpu: 300 })).toMatch(/cpu/);
    expect(ok({ cpu: 1024, memory: 3072 }).memory).toBe(3072);
    expect(err({ env: { AWS_ACCESS_KEY_ID: "x" } })).toMatch(/reserved/);
    expect(err({ env: { "bad-name": "x" } })).toMatch(/env/);
    expect(err({ mode: "env" })).toMatch(/command is required/);
    expect(err({ maxMinutes: 241 })).toMatch(/maxMinutes/);
    expect(err({ files: ["../x"] })).toMatch(/files/);
  });
});

describe("buildTaskDefinition", () => {
  const def = buildTaskDefinition(ok({ command: ["serve"], env: { LOG_LEVEL: "info" }, user: "1000" }), base);
  const init = def.containerDefinitions!.find((c) => c.name === INIT)!;
  const app = def.containerDefinitions!.find((c) => c.name === APP)!;

  it("runs the app read-only, non-root, capability-free, only after init succeeded", () => {
    expect(app).toMatchObject({
      image: IMG,
      user: "1000:1000",
      readonlyRootFilesystem: true,
      essential: true,
      dependsOn: [{ containerName: INIT, condition: "SUCCESS" }],
      linuxParameters: { capabilities: { drop: ["ALL"] }, initProcessEnabled: true },
      command: ["serve"],
    });
    expect(app.mountPoints).toContainEqual({ sourceVolume: "secrets", containerPath: "/run/secrets", readOnly: true });
  });

  it("never puts a secret in the task definition", () => {
    const text = JSON.stringify(def);
    expect(app.environment).toEqual([{ name: "LOG_LEVEL", value: "info" }]);
    expect(text).not.toMatch(/token|nonce|password/i);
  });

  it("gives init only CHOWN and hands the files to the app's uid", () => {
    expect(init.user).toBe("0");
    expect(init.command).toEqual(["runner-init", "--dest", "/run/secrets", "--owner", "1000:1000"]);
    expect(init.linuxParameters!.capabilities!.drop).not.toContain("CHOWN");
    expect(init.linuxParameters!.capabilities!.drop).toContain("DAC_OVERRIDE");
    expect(init.readonlyRootFilesystem).toBe(true);
    expect(init.essential).toBe(false);
  });

  it("wraps the command in env mode", () => {
    const envDef = buildTaskDefinition(ok({ mode: "env", command: ["node", "server.js"] }), base);
    const a = envDef.containerDefinitions!.find((c) => c.name === APP)!;
    expect(a.entryPoint).toEqual(["/bin/sh", "-c", '. /run/secrets/env.sh && exec "$@"', "enclave-run"]);
    expect(a.command).toEqual(["node", "server.js"]);
  });

  it("is a Fargate awsvpc definition with per-task volumes", () => {
    expect(def).toMatchObject({ requiresCompatibilities: ["FARGATE"], networkMode: "awsvpc", cpu: "256", memory: "512" });
    expect(def.volumes!.map((v) => v.name)).toEqual(["secrets", "init-tmp", "app-tmp"]);
  });

  it("extracts the task id", () => {
    expect(taskIdOf("arn:aws:ecs:eu-central-1:1:task/runner/0123456789abcdef0123456789abcdef")).toBe("0123456789abcdef0123456789abcdef");
  });
});
