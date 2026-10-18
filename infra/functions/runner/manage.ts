import { ECSClient, DescribeTasksCommand, StopTaskCommand } from "@aws-sdk/client-ecs";
import { CloudWatchLogsClient, GetLogEventsCommand } from "@aws-sdk/client-cloudwatch-logs";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand } from "@aws-sdk/lib-dynamodb";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { authorize } from "../lib/access.js";
import { record } from "../lib/audit.js";
import { featureEnabled } from "../lib/features.js";
import { requirePrincipal, type Claims } from "../lib/jwt.js";
import { APP, INIT } from "../lib/runner.js";
import { ok, badRequest, unauthorized, forbidden, json, parseBody } from "../lib/response.js";
import { edgeRejection } from "../lib/edge.js";

/**
 * POST /runner/status | /runner/stop | /runner/logs   { runId, ... }
 *
 * Whoever can read the run's project/stage can see, stop and tail it. An
 * unknown run and a run you cannot see answer the same 404.
 */

const ecs = new ECSClient({ region: process.env.ENCLAVE_REGION });
const logs = new CloudWatchLogsClient({ region: process.env.ENCLAVE_REGION });
const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region: process.env.ENCLAVE_REGION }));

const notFound = () => json(404, { error: "no such run" });
const RUN_ID = /^[0-9a-f]{32}$/;

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
  if (claims.run) return forbidden("runner tokens cannot manage runs");

  const op = event.rawPath.split("/").filter(Boolean).at(-1);
  const body = parseBody<{ runId?: unknown; container?: unknown; nextToken?: unknown }>(event);
  if (typeof body.runId !== "string" || !RUN_ID.test(body.runId)) return badRequest("a valid runId is required");

  const found = await ddb.send(new GetCommand({ TableName: process.env.RUN_TABLE!, Key: { runId: body.runId } }));
  const run = found.Item;
  if (!run || !(await authorize(claims, run.project, run.stage, "read"))) return notFound();

  const cluster = process.env.RUNNER_CLUSTER!;

  if (op === "status") {
    const out = await ecs.send(new DescribeTasksCommand({ cluster, tasks: [run.taskArn] }));
    const task = out.tasks?.[0];
    const app = task?.containers?.find((c) => c.name === APP);
    const init = task?.containers?.find((c) => c.name === INIT);
    return ok({
      runId: run.runId,
      project: run.project,
      stage: run.stage,
      image: run.image,
      mode: run.mode,
      requestedBy: run.requestedBy,
      createdAt: run.createdAt,
      deadline: run.deadline,
      // ECS forgets stopped tasks after about an hour.
      status: task?.lastStatus ?? "STOPPED",
      desiredStatus: task?.desiredStatus ?? "STOPPED",
      startedAt: task?.startedAt?.toISOString(),
      stoppedAt: task?.stoppedAt?.toISOString(),
      stoppedReason: task?.stoppedReason,
      exitCode: app?.exitCode,
      initExitCode: init?.exitCode,
      initReason: init?.reason,
    });
  }

  if (op === "stop") {
    await record(event, { claims, project: run.project, stage: run.stage, action: "run.stop", detail: { runId: run.runId } });
    await ecs.send(new StopTaskCommand({ cluster, task: run.taskArn, reason: `stopped by ${claims.sub}`.slice(0, 255) }));
    return ok({ ok: true });
  }

  if (op === "logs") {
    const container = body.container === "init" ? INIT : APP;
    const prefix = container === INIT ? "init" : "app";
    try {
      const out = await logs.send(
        new GetLogEventsCommand({
          logGroupName: process.env.RUNNER_LOG_GROUP!,
          logStreamName: `${prefix}/${container}/${run.runId}`,
          startFromHead: true,
          nextToken: typeof body.nextToken === "string" ? body.nextToken : undefined,
          limit: 500,
        }),
      );
      return ok({
        events: (out.events ?? []).map((e) => ({ timestamp: e.timestamp, message: e.message })),
        nextToken: out.nextForwardToken,
      });
    } catch (err) {
      // The stream does not exist until the container has started.
      if ((err as { name?: string }).name === "ResourceNotFoundException") {
        return ok({ events: [], nextToken: typeof body.nextToken === "string" ? body.nextToken : null });
      }
      throw err;
    }
  }

  return badRequest("unknown runner operation");
}
