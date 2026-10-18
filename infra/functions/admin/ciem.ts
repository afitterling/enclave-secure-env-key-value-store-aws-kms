import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, QueryCommand } from "@aws-sdk/lib-dynamodb";
import { validStages } from "../lib/access.js";
import { featureEnabled } from "../lib/features.js";
import { analyze, buildEntitlements, utilization } from "../lib/ciem.js";
import { ok, badRequest } from "../lib/response.js";

/**
 * CIEM routes, mounted by admin/handler.ts (owner only, `ciem` feature):
 *
 *   GET /admin/projects/{p}/entitlements   every path to every stage + findings
 *   GET /admin/projects/{p}/audit          newest-first event log (?limit, ?cursor, ?principal)
 */

const ddb = DynamoDBDocumentClient.from(
  new DynamoDBClient({ region: process.env.ENCLAVE_REGION }),
);

async function queryAll(table: string, pk: string, skPrefix?: string) {
  const items: Record<string, unknown>[] = [];
  let start: Record<string, unknown> | undefined;
  do {
    const out = await ddb.send(
      new QueryCommand({
        TableName: table,
        KeyConditionExpression: skPrefix ? "pk = :p AND begins_with(sk, :s)" : "pk = :p",
        ExpressionAttributeValues: skPrefix ? { ":p": pk, ":s": skPrefix } : { ":p": pk },
        ExclusiveStartKey: start,
      }),
    );
    items.push(...((out.Items ?? []) as Record<string, unknown>[]));
    start = out.LastEvaluatedKey;
  } while (start);
  return items;
}

export async function entitlements(project: string) {
  const access = process.env.ACCESS_TABLE!;
  const audit = process.env.AUDIT_TABLE!;
  const items = await queryAll(access, `PROJECT#${project}`);
  const members = items.filter((i) => (i.sk as string).startsWith("MEMBER#"));
  const machines = items.filter((i) => (i.sk as string).startsWith("MACHINE#"));

  // Team grants (enterprise `teams`): PROJECT#<p>/TEAM#<t> plus TEAM#<t>/MEMBER#<email>.
  const teamGrants = featureEnabled("teams")
    ? await Promise.all(
        items
          .filter((i) => (i.sk as string).startsWith("TEAM#"))
          .map(async (g) => ({
            team: (g.sk as string).slice("TEAM#".length),
            stages: (g.stages as string[]) ?? [],
            grantedAt: g.createdAt as string | undefined,
            members: (await queryAll(access, g.sk as string, "MEMBER#")).map((m) =>
              (m.sk as string).slice("MEMBER#".length),
            ),
          })),
      )
    : [];

  const usage = await queryAll(audit, `USAGE#${project}`);
  const windowDays = Number(process.env.CIEM_UNUSED_DAYS ?? "30");
  const stages = validStages();
  const ents = buildEntitlements({ members, machines, teamGrants, usage, stages });
  const findings = analyze(ents, machines, { windowDays, stages });
  return ok({
    project,
    windowDays,
    utilization: utilization(ents, windowDays),
    entitlements: ents,
    findings,
  });
}

export async function auditLog(project: string, query: Record<string, string | undefined>) {
  const table = process.env.AUDIT_TABLE!;
  const limit = Math.min(Math.max(Number(query.limit ?? "50") || 50, 1), 200);
  let start: Record<string, unknown> | undefined;
  if (query.cursor) {
    try {
      start = JSON.parse(Buffer.from(query.cursor, "base64url").toString("utf8"));
    } catch {
      return badRequest("invalid cursor");
    }
    // A cursor must stay inside this project's partition.
    if (!start || start.pk !== `PROJECT#${project}`) return badRequest("invalid cursor");
  }
  const out = await ddb.send(
    new QueryCommand({
      TableName: table,
      KeyConditionExpression: "pk = :p",
      ExpressionAttributeValues: {
        ":p": `PROJECT#${project}`,
        ...(query.principal ? { ":who": query.principal } : {}),
      },
      ...(query.principal ? { FilterExpression: "principal = :who OR actor = :who" } : {}),
      ScanIndexForward: false,
      Limit: limit,
      ExclusiveStartKey: start,
    }),
  );
  const events = (out.Items ?? []).map((i) => ({
    at: (i.sk as string).split("#")[0],
    principal: i.principal,
    kind: i.kind,
    actor: i.actor,
    stage: i.stage,
    action: i.action,
    file: i.file,
    ip: i.ip,
    src: i.src,
    detail: i.detail,
  }));
  const cursor = out.LastEvaluatedKey
    ? Buffer.from(JSON.stringify(out.LastEvaluatedKey)).toString("base64url")
    : null;
  return ok({ events, cursor });
}

/**
 * Parse an owner-supplied grant lifetime. `expiresInHours` (1..720) is the
 * just-in-time form; `null`/absent means a standing grant. Returns undefined
 * for "no expiry", a string for an ISO deadline, or an error message.
 */
export function grantExpiry(body: Record<string, unknown>): { at?: string } | { error: string } {
  const hours = body.expiresInHours;
  if (hours === undefined || hours === null || hours === "") return {};
  if (!featureEnabled("ciem")) return { error: "time-boxed grants need the ciem feature" };
  if (typeof hours !== "number" || !Number.isFinite(hours) || hours < 1 || hours > 720) {
    return { error: "expiresInHours must be between 1 and 720" };
  }
  return { at: new Date(Date.now() + hours * 3_600_000).toISOString() };
}
