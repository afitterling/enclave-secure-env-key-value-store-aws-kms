import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { issueMachine, issueRunner, verify } from "../lib/jwt.js";
import { record } from "../lib/audit.js";
import { verifyOidcToken } from "../lib/oidc.js";
import { verifySignedStsRequest, SERVER_ID_HEADER, type SignedStsRequest } from "../lib/awsiam.js";
import { claimsMatch, parseCallerArn, toBinding } from "../lib/machines.js";
import { featureEnabled } from "../lib/features.js";
import { ok, badRequest, unauthorized, forbidden, parseBody } from "../lib/response.js";
import { edgeRejection } from "../lib/edge.js";

/**
 * Workload login: trade a workload's own identity for a short-lived machine
 * token scoped to one binding.
 *
 *   GET  /auth/workload   -> { audience, serverIdHeader }   (what to request a token for)
 *   POST /auth/workload   { project, identity, oidcToken }  OIDC (GitHub, GitLab, K8s, ...)
 *                         { project, identity, aws: {...} } signed sts:GetCallerIdentity
 *                         { runner: true, aws: {...} }      cloud-runner init container
 *
 * The workload never holds a long-lived enclave credential, and we never hold
 * one of theirs. Every failure answers the same generic 401 so the endpoint
 * cannot be used to probe which projects or bindings exist; the reason goes to
 * the function log only.
 */

const MACHINE_TTL = 900; // seconds

const ddb = DynamoDBDocumentClient.from(
  new DynamoDBClient({ region: process.env.ENCLAVE_REGION }),
);

const safeName = (name: unknown): name is string =>
  typeof name === "string" && /^[\w.@+-]+$/.test(name) && name.length <= 64;

interface Body {
  runner?: unknown;
  project?: unknown;
  identity?: unknown;
  oidcToken?: unknown;
  aws?: SignedStsRequest;
}

export async function handler(event: APIGatewayProxyEventV2) {
  // Reject anything that did not come through CloudFront (see lib/edge.ts).
  const blocked = edgeRejection(event);
  if (blocked) return blocked;
  if (!featureEnabled("machineIdentities")) return forbidden("machine identities are not enabled");

  const audience = process.env.WORKLOAD_AUDIENCE!;
  if (event.requestContext.http.method === "GET") {
    return ok({ audience, serverIdHeader: SERVER_ID_HEADER });
  }

  const body = parseBody<Body>(event);
  if (body.runner === true) return runnerLogin(event, body.aws, audience);

  const { project, identity, oidcToken, aws } = body;
  if (!safeName(project) || !safeName(identity)) return badRequest("project and identity are required");
  if (!oidcToken === !aws) return badRequest("send exactly one of oidcToken or aws");

  const generic = unauthorized("workload authentication failed");
  const deny = (reason: string) => {
    console.warn(JSON.stringify({ msg: "workload login denied", project, identity, reason }));
    return generic;
  };

  const out = await ddb.send(
    new GetCommand({
      TableName: process.env.ACCESS_TABLE!,
      Key: { pk: `PROJECT#${project}`, sk: `MACHINE#${identity}` },
    }),
  );
  if (!out.Item) return deny("no such binding");
  const binding = toBinding(out.Item);

  let src: string;
  try {
    if (oidcToken) {
      if (binding.kind !== "oidc" || !binding.issuer || !binding.claims) return deny("binding is not oidc");
      const claims = await verifyOidcToken(
        oidcToken as string,
        binding.issuer,
        binding.audience ?? audience,
      );
      if (!claimsMatch(binding.claims, claims)) return deny("claims do not match");
      src = `${binding.issuer}#${String(claims.sub)}`;
    } else {
      if (binding.kind !== "aws") return deny("binding is not aws");
      const caller = await verifySignedStsRequest(aws!, audience);
      const parsed = parseCallerArn(caller.arn);
      if (!parsed) return deny(`caller ${caller.arn} is not a role`);
      if (parsed.account !== binding.account || parsed.role !== binding.role) {
        return deny(`caller ${caller.arn} does not match`);
      }
      src = caller.arn;
    }
  } catch (err) {
    return deny((err as Error).message);
  }

  const token = issueMachine(
    { prj: project, mid: identity, rev: binding.rev, src },
    process.env.JWT_SIGNING_KEY!,
    MACHINE_TTL,
  );
  console.log(JSON.stringify({ msg: "workload login", project, identity, src }));
  await record(event, {
    claims: verify(token, process.env.JWT_SIGNING_KEY!),
    project,
    stage: binding.stages.join(","),
    action: "workload.login",
  });
  return ok({
    token,
    principal: `machine:${project}/${identity}`,
    project,
    stages: binding.stages,
    access: binding.access,
    expiresIn: MACHINE_TTL,
  });
}

/**
 * Cloud-runner init login (enterprise `cloudRunner`). The init container signs
 * sts:GetCallerIdentity with the runner task role. ECS names that role's
 * session after the task id and the role trusts only ECS tasks in this
 * account, so the session name identifies the run. The login is one-time: the
 * run record is marked consumed in the same conditional write that checks it.
 */
async function runnerLogin(event: APIGatewayProxyEventV2, aws: SignedStsRequest | undefined, audience: string) {
  const generic = unauthorized("workload authentication failed");
  const deny = (reason: string) => {
    console.warn(JSON.stringify({ msg: "runner login denied", reason }));
    return generic;
  };
  if (!featureEnabled("cloudRunner") || !process.env.RUN_TABLE) return deny("runner disabled");
  if (!aws) return badRequest("aws is required");

  let arn: string;
  let runId: string;
  try {
    const caller = await verifySignedStsRequest(aws, audience);
    const parsed = parseCallerArn(caller.arn);
    if (
      !parsed?.session ||
      parsed.account !== process.env.RUNNER_ACCOUNT ||
      parsed.role !== process.env.RUNNER_TASK_ROLE_NAME ||
      !/^[0-9a-f]{32}$/.test(parsed.session)
    ) {
      return deny(`caller ${caller.arn} is not a runner task`);
    }
    arn = caller.arn;
    runId = parsed.session;
  } catch (err) {
    return deny((err as Error).message);
  }

  let run: Record<string, unknown>;
  try {
    const out = await ddb.send(
      new UpdateCommand({
        TableName: process.env.RUN_TABLE,
        Key: { runId },
        UpdateExpression: "SET loggedInAt = :now",
        ConditionExpression: "attribute_exists(runId) AND attribute_not_exists(loggedInAt) AND deadline > :epoch",
        ExpressionAttributeValues: { ":now": new Date().toISOString(), ":epoch": Math.floor(Date.now() / 1000) },
        ReturnValues: "ALL_NEW",
      }),
    );
    run = out.Attributes!;
  } catch (err) {
    // Not written yet (the init container retries), already used, or past its deadline.
    if ((err as { name?: string }).name === "ConditionalCheckFailedException") return deny(`run ${runId} not claimable`);
    throw err;
  }

  const project = run.project as string;
  const stage = run.stage as string;
  const token = issueRunner(
    { prj: project, run: runId, rev: run.nonce as string, src: arn, act: run.requestedBy as string },
    process.env.JWT_SIGNING_KEY!,
    MACHINE_TTL,
  );
  await record(event, {
    claims: verify(token, process.env.JWT_SIGNING_KEY!),
    project,
    stage,
    action: "workload.login",
    actor: run.requestedBy as string,
    detail: { runId },
  });
  return ok({
    token,
    principal: `runner:${runId}`,
    project,
    stages: [stage],
    access: "read",
    files: run.files ?? [],
    mode: run.mode ?? "files",
    expiresIn: MACHINE_TTL,
  });
}
