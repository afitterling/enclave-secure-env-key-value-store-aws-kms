import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, PutCommand, QueryCommand } from "@aws-sdk/lib-dynamodb";
import { featureEnabled } from "./features.js";
import type { Claims } from "./jwt.js";

/**
 * Dynamic access map backed by DynamoDB (ACCESS_TABLE), replacing the old
 * static users.yaml. Item shapes (single table, gsi1 = gsi1pk/gsi1sk):
 *
 *   PROJECT#<p> / META            { owner, createdAt }
 *   PROJECT#<p> / MEMBER#<email>  { role: owner|member, stages[], addedBy }   gsi1: USER#<email> -> PROJECT#<p>
 *   PROJECT#<p> / TEAM#<t>        { stages[], grantedBy }                     gsi1: TEAM#<t>     -> PROJECT#<p>
 *   TEAM#<t>    / META            { owner, createdAt }
 *   TEAM#<t>    / MEMBER#<email>  { addedBy }                                 gsi1: USER#<email> -> TEAM#<t>
 *   USER#<email> / PROFILE        { createdAt, via: "signup" }                gsi1: USER#<email> -> PROFILE
 *   PROJECT#<p> / MACHINE#<id>    machine-identity binding (lib/machines.ts)  no gsi1: not a user
 *
 * An email is "known" (may request a login code) if it is an admin
 * (ADMIN_EMAILS env, comma-separated) or has any gsi1 item: a membership from
 * an invite, or a PROFILE from self-service signup (the `signup` feature).
 *
 * No module-scope caching of results: access changes must apply immediately.
 */

const ddb = DynamoDBDocumentClient.from(
  new DynamoDBClient({ region: process.env.ENCLAVE_REGION }),
);

const table = () => process.env.ACCESS_TABLE!;

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function adminEmails(): string[] {
  return (process.env.ADMIN_EMAILS ?? "")
    .split(",")
    .map((e) => normalizeEmail(e))
    .filter(Boolean);
}

export function validStages(): string[] {
  return JSON.parse(process.env.STAGES ?? "[]");
}

interface MemberItem {
  role?: "owner" | "member";
  stages?: string[];
  grantExpiresAt?: string;
}

/** Time-boxed grants (CIEM): an ISO `grantExpiresAt` on a membership or a
 * machine binding. Past it, the grant is ignored everywhere; the item stays so
 * the entitlement view can show it as expired until someone cleans it up. */
export function grantExpired(item: { grantExpiresAt?: unknown } | undefined): boolean {
  const at = item?.grantExpiresAt;
  return typeof at === "string" && Date.parse(at) <= Date.now();
}

interface GrantItem {
  sk: string; // TEAM#<t>
  stages?: string[];
}

/** May this email log in at all? Admins always; otherwise any membership. */
export async function isKnownUser(email: string): Promise<boolean> {
  const e = normalizeEmail(email);
  if (adminEmails().includes(e)) return true;
  const out = await ddb.send(
    new QueryCommand({
      TableName: table(),
      IndexName: "gsi1",
      KeyConditionExpression: "gsi1pk = :u",
      ExpressionAttributeValues: { ":u": `USER#${e}` },
      Limit: 1,
    }),
  );
  return (out.Count ?? 0) > 0;
}

/**
 * Record a self-service signup, which makes the email known from then on.
 * Idempotent: an existing profile is left as it was.
 */
export async function registerUser(email: string): Promise<void> {
  const e = normalizeEmail(email);
  try {
    await ddb.send(
      new PutCommand({
        TableName: table(),
        Item: {
          pk: `USER#${e}`,
          sk: "PROFILE",
          gsi1pk: `USER#${e}`,
          gsi1sk: "PROFILE",
          via: "signup",
          createdAt: new Date().toISOString(),
        },
        ConditionExpression: "attribute_not_exists(pk)",
      }),
    );
  } catch (err: unknown) {
    if ((err as { name?: string }).name !== "ConditionalCheckFailedException") throw err;
  }
}

/** Everything this user can touch: { project: [stages] }. Direct + via teams. */
export async function permissionsFor(email: string): Promise<Record<string, string[]>> {
  const e = normalizeEmail(email);
  const stages = validStages();
  const merged = new Map<string, Set<string>>();

  const add = (project: string, granted: string[]) => {
    const set = merged.get(project) ?? new Set<string>();
    for (const s of granted) if (stages.includes(s)) set.add(s);
    merged.set(project, set);
  };

  const finish = () => {
    const out: Record<string, string[]> = {};
    for (const [project, set] of merged) {
      out[project] = stages.filter((s) => set.has(s));
    }
    return out;
  };

  const mine = await ddb.send(
    new QueryCommand({
      TableName: table(),
      IndexName: "gsi1",
      KeyConditionExpression: "gsi1pk = :u",
      ExpressionAttributeValues: { ":u": `USER#${e}` },
    }),
  );

  const teamIds: string[] = [];
  for (const item of mine.Items ?? []) {
    const target = item.gsi1sk as string;
    if (target.startsWith("PROJECT#")) {
      if (item.role !== "owner" && grantExpired(item)) continue;
      const project = target.slice("PROJECT#".length);
      add(project, item.role === "owner" ? stages : ((item.stages as string[]) ?? []));
    } else if (target.startsWith("TEAM#")) {
      teamIds.push(target.slice("TEAM#".length));
    }
  }

  // Grants held by each team the user belongs to (enterprise feature —
  // disabled teams grant nothing, even if grant items exist in the table).
  if (!featureEnabled("teams")) return finish();
  for (const team of teamIds) {
    const grants = await ddb.send(
      new QueryCommand({
        TableName: table(),
        IndexName: "gsi1",
        KeyConditionExpression: "gsi1pk = :t",
        ExpressionAttributeValues: { ":t": `TEAM#${team}` },
      }),
    );
    for (const g of grants.Items ?? []) {
      const target = g.gsi1sk as string;
      if (target.startsWith("PROJECT#")) {
        add(target.slice("PROJECT#".length), (g.stages as string[]) ?? []);
      }
    }
  }

  return finish();
}

/**
 * Authoritative check used by every privileged endpoint. Fails closed:
 *   - stage not a configured stage        -> false (no bucket-policy role exists)
 *   - direct membership: owner            -> true
 *   - direct membership: member           -> stage listed on the membership
 *   - else: any team the user is in with a grant covering (project, stage)
 */
export async function canAccess(email: string, project: string, stage: string): Promise<boolean> {
  if (!validStages().includes(stage)) return false;
  const e = normalizeEmail(email);

  const direct = await ddb.send(
    new GetCommand({
      TableName: table(),
      Key: { pk: `PROJECT#${project}`, sk: `MEMBER#${e}` },
    }),
  );
  const member = direct.Item as MemberItem | undefined;
  if (member) {
    if (member.role === "owner") return true;
    if (grantExpired(member)) return false;
    if (Array.isArray(member.stages) && member.stages.includes(stage)) return true;
  }

  // Team path (enterprise feature): grants on this project whose stages
  // include `stage`, where the user is a member of the granted team.
  if (!featureEnabled("teams")) return false;
  const grants = await ddb.send(
    new QueryCommand({
      TableName: table(),
      KeyConditionExpression: "pk = :p AND begins_with(sk, :t)",
      ExpressionAttributeValues: { ":p": `PROJECT#${project}`, ":t": "TEAM#" },
    }),
  );
  for (const g of (grants.Items ?? []) as GrantItem[]) {
    if (!Array.isArray(g.stages) || !g.stages.includes(stage)) continue;
    const membership = await ddb.send(
      new GetCommand({
        TableName: table(),
        Key: { pk: g.sk, sk: `MEMBER#${e}` },
      }),
    );
    if (membership.Item) return true;
  }
  return false;
}

export type VaultAction = "read" | "write";

/**
 * The one gate in front of KMS and S3, for both kinds of principal:
 *
 *   human   -> canAccess(): owners and members, no read/write distinction
 *   machine -> the binding named in the token, re-read now: it must still
 *              exist with the same `rev`, belong to the token's project,
 *              list the stage, and grant `write` for writes
 *
 * Both paths read DynamoDB on every call, so removing a member or a binding
 * takes effect on the next request, not when a token expires.
 */
export async function authorize(
  claims: Claims,
  project: string,
  stage: string,
  action: VaultAction,
): Promise<boolean> {
  if (claims.typ !== "machine") return canAccess(claims.sub, project, stage);

  if (!validStages().includes(stage)) return false;
  if (claims.prj !== project) return false;
  if (claims.run) return authorizeRunner(claims, project, stage, action);

  if (!featureEnabled("machineIdentities")) return false;
  const out = await ddb.send(
    new GetCommand({
      TableName: table(),
      Key: { pk: `PROJECT#${project}`, sk: `MACHINE#${claims.mid}` },
    }),
  );
  const binding = out.Item;
  if (!binding || binding.rev !== claims.rev || grantExpired(binding)) return false;
  if (!Array.isArray(binding.stages) || !binding.stages.includes(stage)) return false;
  return action === "read" || binding.access === "write";
}

/**
 * Cloud-runner tokens (enterprise `cloudRunner` feature) are read-only, valid
 * only for the run's own project and stage, and only while the run record
 * exists with the same nonce and its deadline has not passed.
 */
async function authorizeRunner(
  claims: Claims,
  project: string,
  stage: string,
  action: VaultAction,
): Promise<boolean> {
  if (!featureEnabled("cloudRunner") || action !== "read" || !process.env.RUN_TABLE) return false;
  const out = await ddb.send(
    new GetCommand({ TableName: process.env.RUN_TABLE, Key: { runId: claims.run } }),
  );
  const run = out.Item;
  if (!run || run.nonce !== claims.rev) return false;
  if (run.project !== project || run.stage !== stage) return false;
  return typeof run.deadline === "number" && run.deadline > Math.floor(Date.now() / 1000);
}
