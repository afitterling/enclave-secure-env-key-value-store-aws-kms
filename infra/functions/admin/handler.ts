import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  QueryCommand,
  PutCommand,
  DeleteCommand,
  TransactWriteCommand,
} from "@aws-sdk/lib-dynamodb";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { normalizeEmail, validStages } from "../lib/access.js";
import { featureEnabled } from "../lib/features.js";
import { requireAuth } from "../lib/jwt.js";
import { ok, badRequest, unauthorized, forbidden, json, parseBody } from "../lib/response.js";

/**
 * Self-service project/team administration. One Lambda, internal router:
 *
 *   GET  /admin/projects                          list my projects
 *   POST /admin/projects                          { project }            create; caller becomes owner
 *   GET  /admin/projects/{p}                      detail (members only)
 *   POST /admin/projects/{p}/members              { email, stages }      owner only (upsert)
 *   POST /admin/projects/{p}/members/remove       { email }              owner only
 *   POST /admin/projects/{p}/teams                { team, stages }       owner only (upsert grant)
 *   POST /admin/projects/{p}/teams/remove         { team }               owner only
 *   GET  /admin/teams                             list my teams
 *   POST /admin/teams                             { team }               create; caller becomes owner
 *   GET  /admin/teams/{t}                         detail (members only)
 *   POST /admin/teams/{t}/members                 { email }              owner only
 *   POST /admin/teams/{t}/members/remove          { email }              owner only
 *
 * Mutations are POST-only so the API-GW CORS surface stays GET/POST.
 * Ids share the S3-safe regex with presign. Stage lists are validated
 * against the fixed STAGES set at write time.
 */

const ddb = DynamoDBDocumentClient.from(
  new DynamoDBClient({ region: process.env.ENCLAVE_REGION }),
);
const TABLE = () => process.env.ACCESS_TABLE!;

const safeName = (name: string) => /^[\w.@+-]+$/.test(name);
// Pragmatic address check: local@domain.tld, no spaces, one @.
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const conflict = (msg: string) => json(409, { error: msg });
const notFound = (msg = "not found") => json(404, { error: msg });

function validStageList(stages: unknown): string[] | null {
  if (!Array.isArray(stages)) return null;
  const input = [...new Set(stages)].filter((s): s is string => typeof s === "string");
  if (input.length === 0) return null;
  const valid = validStages();
  if (!input.every((s) => valid.includes(s))) return null; // any unknown stage -> reject
  return valid.filter((s) => input.includes(s)); // canonical order, deduped
}

async function getMeta(pk: string) {
  const out = await ddb.send(new GetCommand({ TableName: TABLE(), Key: { pk, sk: "META" } }));
  return out.Item;
}

async function getMember(pk: string, email: string) {
  const out = await ddb.send(
    new GetCommand({ TableName: TABLE(), Key: { pk, sk: `MEMBER#${email}` } }),
  );
  return out.Item;
}

async function queryPrefix(pk: string, skPrefix: string) {
  const out = await ddb.send(
    new QueryCommand({
      TableName: TABLE(),
      KeyConditionExpression: "pk = :p AND begins_with(sk, :s)",
      ExpressionAttributeValues: { ":p": pk, ":s": skPrefix },
    }),
  );
  return out.Items ?? [];
}

/** Create PROJECT#/TEAM# meta + owner membership atomically; false if name taken. */
async function createEntity(pk: string, gsi1sk: string, email: string): Promise<boolean> {
  const createdAt = new Date().toISOString();
  try {
    await ddb.send(
      new TransactWriteCommand({
        TransactItems: [
          {
            Put: {
              TableName: TABLE(),
              Item: { pk, sk: "META", owner: email, createdAt },
              ConditionExpression: "attribute_not_exists(pk)",
            },
          },
          {
            Put: {
              TableName: TABLE(),
              Item: {
                pk,
                sk: `MEMBER#${email}`,
                gsi1pk: `USER#${email}`,
                gsi1sk,
                role: "owner",
                addedBy: email,
                createdAt,
              },
            },
          },
        ],
      }),
    );
    return true;
  } catch (err: unknown) {
    const name = (err as { name?: string }).name ?? "";
    if (name === "TransactionCanceledException" || name === "ConditionalCheckFailedException") {
      return false;
    }
    throw err;
  }
}

// ---- projects --------------------------------------------------------------

async function listProjects(email: string) {
  const memberships = await ddb.send(
    new QueryCommand({
      TableName: TABLE(),
      IndexName: "gsi1",
      KeyConditionExpression: "gsi1pk = :u AND begins_with(gsi1sk, :p)",
      ExpressionAttributeValues: { ":u": `USER#${email}`, ":p": "PROJECT#" },
    }),
  );
  const projects = await Promise.all(
    (memberships.Items ?? []).map(async (m) => {
      const project = (m.gsi1sk as string).slice("PROJECT#".length);
      const meta = await getMeta(`PROJECT#${project}`);
      return {
        project,
        role: m.role as string,
        stages: m.role === "owner" ? validStages() : ((m.stages as string[]) ?? []),
        owner: (meta?.owner as string) ?? null,
      };
    }),
  );
  return ok({ projects: projects.sort((a, b) => a.project.localeCompare(b.project)) });
}

async function createProject(email: string, body: Record<string, unknown>) {
  const project = typeof body.project === "string" ? body.project : "";
  if (!project || !safeName(project)) return badRequest("a valid project name is required");
  const created = await createEntity(`PROJECT#${project}`, `PROJECT#${project}`, email);
  if (!created) return conflict("project name is already taken");
  return ok({ project, role: "owner" });
}

async function projectDetail(email: string, project: string) {
  const meta = await getMeta(`PROJECT#${project}`);
  // Return 404 whether the project is missing OR the caller isn't a member, so
  // the endpoint can't be used to enumerate the global project namespace.
  if (!meta) return notFound("no such project");
  const me = await getMember(`PROJECT#${project}`, email);
  if (!me) return notFound("no such project");
  const members = (await queryPrefix(`PROJECT#${project}`, "MEMBER#")).map((m) => ({
    email: (m.sk as string).slice("MEMBER#".length),
    role: m.role as string,
    stages: m.role === "owner" ? validStages() : ((m.stages as string[]) ?? []),
  }));
  const teams = (await queryPrefix(`PROJECT#${project}`, "TEAM#")).map((t) => ({
    team: (t.sk as string).slice("TEAM#".length),
    stages: (t.stages as string[]) ?? [],
  }));
  return ok({ project, owner: meta.owner as string, members, teams });
}

async function requireOwner(pk: string, email: string) {
  const meta = await getMeta(pk);
  if (!meta) return notFound("no such project/team");
  const me = await getMember(pk, email);
  if (!me || me.role !== "owner") return forbidden("owner access required");
  return null;
}

async function upsertProjectMember(email: string, project: string, body: Record<string, unknown>) {
  const denied = await requireOwner(`PROJECT#${project}`, email);
  if (denied) return denied;
  const invitee = typeof body.email === "string" ? normalizeEmail(body.email) : "";
  if (!EMAIL.test(invitee)) return badRequest("a valid email is required");
  const stages = validStageList(body.stages);
  if (!stages) return badRequest(`stages must be a non-empty subset of ${validStages().join(", ")}`);
  const existing = await getMember(`PROJECT#${project}`, invitee);
  if (existing?.role === "owner") return badRequest("cannot change the owner's access");
  await ddb.send(
    new PutCommand({
      TableName: TABLE(),
      Item: {
        pk: `PROJECT#${project}`,
        sk: `MEMBER#${invitee}`,
        gsi1pk: `USER#${invitee}`,
        gsi1sk: `PROJECT#${project}`,
        role: "member",
        stages,
        addedBy: email,
        createdAt: new Date().toISOString(),
      },
    }),
  );
  return ok({ ok: true });
}

async function removeProjectMember(email: string, project: string, body: Record<string, unknown>) {
  const denied = await requireOwner(`PROJECT#${project}`, email);
  if (denied) return denied;
  const target = typeof body.email === "string" ? normalizeEmail(body.email) : "";
  if (!target) return badRequest("email is required");
  const existing = await getMember(`PROJECT#${project}`, target);
  if (existing?.role === "owner") return badRequest("cannot remove the project owner");
  await ddb.send(
    new DeleteCommand({
      TableName: TABLE(),
      Key: { pk: `PROJECT#${project}`, sk: `MEMBER#${target}` },
    }),
  );
  return ok({ ok: true });
}

async function upsertTeamGrant(email: string, project: string, body: Record<string, unknown>) {
  const denied = await requireOwner(`PROJECT#${project}`, email);
  if (denied) return denied;
  const team = typeof body.team === "string" ? body.team : "";
  if (!team || !safeName(team)) return badRequest("a valid team name is required");
  if (!(await getMeta(`TEAM#${team}`))) return notFound("no such team");
  const stages = validStageList(body.stages);
  if (!stages) return badRequest(`stages must be a non-empty subset of ${validStages().join(", ")}`);
  await ddb.send(
    new PutCommand({
      TableName: TABLE(),
      Item: {
        pk: `PROJECT#${project}`,
        sk: `TEAM#${team}`,
        gsi1pk: `TEAM#${team}`,
        gsi1sk: `PROJECT#${project}`,
        stages,
        grantedBy: email,
        createdAt: new Date().toISOString(),
      },
    }),
  );
  return ok({ ok: true });
}

async function removeTeamGrant(email: string, project: string, body: Record<string, unknown>) {
  const denied = await requireOwner(`PROJECT#${project}`, email);
  if (denied) return denied;
  const team = typeof body.team === "string" ? body.team : "";
  if (!team) return badRequest("team is required");
  await ddb.send(
    new DeleteCommand({
      TableName: TABLE(),
      Key: { pk: `PROJECT#${project}`, sk: `TEAM#${team}` },
    }),
  );
  return ok({ ok: true });
}

// ---- teams -----------------------------------------------------------------

async function listTeams(email: string) {
  const memberships = await ddb.send(
    new QueryCommand({
      TableName: TABLE(),
      IndexName: "gsi1",
      KeyConditionExpression: "gsi1pk = :u AND begins_with(gsi1sk, :t)",
      ExpressionAttributeValues: { ":u": `USER#${email}`, ":t": "TEAM#" },
    }),
  );
  const teams = await Promise.all(
    (memberships.Items ?? []).map(async (m) => {
      const team = (m.gsi1sk as string).slice("TEAM#".length);
      const meta = await getMeta(`TEAM#${team}`);
      return { team, role: m.role as string, owner: (meta?.owner as string) ?? null };
    }),
  );
  return ok({ teams: teams.sort((a, b) => a.team.localeCompare(b.team)) });
}

async function createTeam(email: string, body: Record<string, unknown>) {
  const team = typeof body.team === "string" ? body.team : "";
  if (!team || !safeName(team)) return badRequest("a valid team name is required");
  const created = await createEntity(`TEAM#${team}`, `TEAM#${team}`, email);
  if (!created) return conflict("team name is already taken");
  return ok({ team });
}

async function teamDetail(email: string, team: string) {
  const meta = await getMeta(`TEAM#${team}`);
  if (!meta) return notFound("no such team");
  const me = await getMember(`TEAM#${team}`, email);
  if (!me) return forbidden("not a member of this team");
  const members = (await queryPrefix(`TEAM#${team}`, "MEMBER#")).map((m) => ({
    email: (m.sk as string).slice("MEMBER#".length),
    role: (m.role as string) ?? "member",
  }));
  const grantItems = await ddb.send(
    new QueryCommand({
      TableName: TABLE(),
      IndexName: "gsi1",
      KeyConditionExpression: "gsi1pk = :t AND begins_with(gsi1sk, :p)",
      ExpressionAttributeValues: { ":t": `TEAM#${team}`, ":p": "PROJECT#" },
    }),
  );
  const grants = (grantItems.Items ?? []).map((g) => ({
    project: (g.gsi1sk as string).slice("PROJECT#".length),
    stages: (g.stages as string[]) ?? [],
  }));
  return ok({ team, owner: meta.owner as string, members, grants });
}

async function addTeamMember(email: string, team: string, body: Record<string, unknown>) {
  const denied = await requireOwner(`TEAM#${team}`, email);
  if (denied) return denied;
  const invitee = typeof body.email === "string" ? normalizeEmail(body.email) : "";
  if (!invitee || !invitee.includes("@")) return badRequest("a valid email is required");
  const existing = await getMember(`TEAM#${team}`, invitee);
  if (existing?.role === "owner") return badRequest("cannot change the owner's membership");
  await ddb.send(
    new PutCommand({
      TableName: TABLE(),
      Item: {
        pk: `TEAM#${team}`,
        sk: `MEMBER#${invitee}`,
        gsi1pk: `USER#${invitee}`,
        gsi1sk: `TEAM#${team}`,
        role: "member",
        addedBy: email,
        createdAt: new Date().toISOString(),
      },
    }),
  );
  return ok({ ok: true });
}

async function removeTeamMember(email: string, team: string, body: Record<string, unknown>) {
  const denied = await requireOwner(`TEAM#${team}`, email);
  if (denied) return denied;
  const target = typeof body.email === "string" ? normalizeEmail(body.email) : "";
  if (!target) return badRequest("email is required");
  const existing = await getMember(`TEAM#${team}`, target);
  if (existing?.role === "owner") return badRequest("cannot remove the team owner");
  await ddb.send(
    new DeleteCommand({ TableName: TABLE(), Key: { pk: `TEAM#${team}`, sk: `MEMBER#${target}` } }),
  );
  return ok({ ok: true });
}

// ---- router ----------------------------------------------------------------

export async function handler(event: APIGatewayProxyEventV2) {
  let email: string;
  try {
    email = requireAuth(event, process.env.JWT_SIGNING_KEY!).sub;
  } catch {
    return unauthorized();
  }

  const method = event.requestContext.http.method;
  const parts = event.rawPath.replace(/^\/admin\/?/, "").split("/").filter(Boolean);
  const body = method === "POST" ? parseBody<Record<string, unknown>>(event) : {};
  const [root, id, sub, action] = parts;

  if (id && !safeName(id)) return badRequest("invalid name");

  if (root === "projects") {
    if (!id) return method === "GET" ? listProjects(email) : createProject(email, body);
    if (!sub) return method === "GET" ? projectDetail(email, id) : badRequest("unknown route");
    if (method !== "POST") return badRequest("unknown route");
    if (sub === "members" && !action) return upsertProjectMember(email, id, body);
    if (sub === "members" && action === "remove") return removeProjectMember(email, id, body);
    if (sub === "teams") {
      if (!featureEnabled("teams")) return notFound("teams are not enabled");
      if (!action) return upsertTeamGrant(email, id, body);
      if (action === "remove") return removeTeamGrant(email, id, body);
    }
    return badRequest("unknown route");
  }

  if (root === "teams") {
    if (!featureEnabled("teams")) return notFound("teams are not enabled");
    if (!id) return method === "GET" ? listTeams(email) : createTeam(email, body);
    if (!sub) return method === "GET" ? teamDetail(email, id) : badRequest("unknown route");
    if (method !== "POST") return badRequest("unknown route");
    if (sub === "members" && !action) return addTeamMember(email, id, body);
    if (sub === "members" && action === "remove") return removeTeamMember(email, id, body);
    return badRequest("unknown route");
  }

  return badRequest("unknown route");
}
