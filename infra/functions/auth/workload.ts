import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand } from "@aws-sdk/lib-dynamodb";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { issueMachine } from "../lib/jwt.js";
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

  const { project, identity, oidcToken, aws } = parseBody<Body>(event);
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
  return ok({
    token,
    principal: `machine:${project}/${identity}`,
    project,
    stages: binding.stages,
    access: binding.access,
    expiresIn: MACHINE_TTL,
  });
}
