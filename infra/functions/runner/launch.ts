import { randomBytes } from "node:crypto";
import {
  ECSClient,
  DescribeTaskDefinitionCommand,
  RegisterTaskDefinitionCommand,
  DeregisterTaskDefinitionCommand,
  RunTaskCommand,
} from "@aws-sdk/client-ecs";
import { SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand } from "@aws-sdk/lib-dynamodb";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { authorize } from "../lib/access.js";
import { record } from "../lib/audit.js";
import { featureEnabled } from "../lib/features.js";
import { requirePrincipal, type Claims } from "../lib/jwt.js";
import { buildTaskDefinition, parseRunRequest, taskIdOf, type Base } from "../lib/runner.js";
import { ok, badRequest, unauthorized, forbidden, serverError, parseBody } from "../lib/response.js";
import { edgeRejection } from "../lib/edge.js";

/**
 * POST /runner/launch — start a cloud run (see lib/runner.ts for the design).
 *
 * Needs read access to the project/stage: running a container with a stage's
 * secrets is reading them. Runner tokens cannot launch runs (no chains).
 *
 * Order matters: the run record is written *after* RunTask returns the task id
 * and before the init container can have pulled its image and logged in; the
 * init container retries its login for a minute to cover the gap.
 */

const ecs = new ECSClient({ region: process.env.ENCLAVE_REGION });
const ssm = new SSMClient({ region: process.env.ENCLAVE_REGION });
const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region: process.env.ENCLAVE_REGION }));

const RETAIN_DAYS = 7; // run records outlive the run so status/audit can find them

let base: Base | undefined;

async function loadBase(): Promise<Base> {
  if (base) return base;
  const td = await ecs.send(
    new DescribeTaskDefinitionCommand({ taskDefinition: process.env.RUNNER_BASE_TASK_DEF! }),
  );
  const def = td.taskDefinition!;
  const container = def.containerDefinitions![0];
  const options = container.logConfiguration?.options ?? {};
  const param = await ssm.send(new GetParameterCommand({ Name: process.env.RUNNER_API_URL_PARAM! }));
  base = {
    family: process.env.RUNNER_FAMILY!,
    initImage: container.image!,
    executionRoleArn: def.executionRoleArn!,
    taskRoleArn: def.taskRoleArn!,
    logGroup: options["awslogs-group"]!,
    region: process.env.ENCLAVE_REGION!,
    apiUrl: param.Parameter!.Value!,
  };
  return base;
}

export async function handler(event: APIGatewayProxyEventV2) {
  const blocked = edgeRejection(event);
  if (blocked) return blocked;
  if (!featureEnabled("cloudRunner")) return forbidden("the cloud runner is not enabled");

  let claims: Claims;
  try {
    claims = requirePrincipal(event, process.env.JWT_SIGNING_KEY!);
  } catch {
    return unauthorized();
  }
  if (claims.run) return forbidden("a run cannot launch other runs");

  const registries: string[] = JSON.parse(process.env.RUNNER_REGISTRIES ?? "[]");
  const parsed = parseRunRequest(parseBody<Record<string, unknown>>(event), registries);
  if (!parsed.ok) return badRequest(parsed.error);
  const run = parsed.run;
  if (!(await authorize(claims, run.project, run.stage, "read"))) {
    return forbidden("no access to this project/stage");
  }

  const nonce = randomBytes(16).toString("base64url");
  // The launch is audited (fail-closed) before anything is started.
  await record(event, {
    claims,
    project: run.project,
    stage: run.stage,
    action: "run.launch",
    detail: { image: run.image, mode: run.mode },
  });

  const registered = await ecs.send(new RegisterTaskDefinitionCommand(buildTaskDefinition(run, await loadBase())));
  const taskDefinitionArn = registered.taskDefinition!.taskDefinitionArn!;

  let taskArn: string | undefined;
  try {
    const started = await ecs.send(
      new RunTaskCommand({
        cluster: process.env.RUNNER_CLUSTER!,
        taskDefinition: taskDefinitionArn,
        launchType: "FARGATE",
        count: 1,
        startedBy: "enclave-runner",
        networkConfiguration: {
          awsvpcConfiguration: {
            subnets: JSON.parse(process.env.RUNNER_SUBNETS!),
            securityGroups: JSON.parse(process.env.RUNNER_SECURITY_GROUPS!),
            assignPublicIp: process.env.RUNNER_PUBLIC_IP === "true" ? "ENABLED" : "DISABLED",
          },
        },
      }),
    );
    taskArn = started.tasks?.[0]?.taskArn;
    if (!taskArn) {
      console.error(JSON.stringify({ msg: "RunTask started nothing", failures: started.failures }));
      return serverError(`could not start the run: ${started.failures?.[0]?.reason ?? "unknown"}`);
    }
  } finally {
    // A running task keeps its (now inactive) revision; deregistering right
    // away stops one-off revisions piling up in the family.
    await ecs
      .send(new DeregisterTaskDefinitionCommand({ taskDefinition: taskDefinitionArn }))
      .catch((err) => console.warn(JSON.stringify({ msg: "deregister failed", err: String(err) })));
  }

  const runId = taskIdOf(taskArn);
  const now = Math.floor(Date.now() / 1000);
  await ddb.send(
    new PutCommand({
      TableName: process.env.RUN_TABLE!,
      Item: {
        runId,
        taskArn,
        nonce,
        project: run.project,
        stage: run.stage,
        image: run.image,
        files: run.files,
        mode: run.mode,
        requestedBy: claims.sub,
        createdAt: new Date().toISOString(),
        deadline: now + run.maxMinutes * 60,
        expiresAt: now + run.maxMinutes * 60 + RETAIN_DAYS * 86400,
      },
    }),
  );
  return ok({ runId, status: "PROVISIONING", maxMinutes: run.maxMinutes, mode: run.mode });
}
