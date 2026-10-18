import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import { analyze, buildEntitlements, utilization } from "../functions/lib/ciem.js";
import { authorize, canAccess, grantExpired } from "../functions/lib/access.js";
import { issueRunner, requirePrincipal } from "../functions/lib/jwt.js";
import { record } from "../functions/lib/audit.js";
import { GITHUB_ISSUER } from "../functions/lib/machines.js";

process.env.STAGES = JSON.stringify(["dev", "staging", "prod", "personal"]);
process.env.ACCESS_TABLE = "access";
const STAGES = ["dev", "staging", "prod", "personal"];
const NOW = Date.parse("2026-10-19T12:00:00Z");
const daysAgo = (d: number) => new Date(NOW - d * 86_400_000).toISOString();

const member = (email: string, stages: string[], extra: Record<string, unknown> = {}) => ({
  pk: "PROJECT#webapp",
  sk: `MEMBER#${email}`,
  role: "member",
  stages,
  createdAt: daysAgo(90),
  ...extra,
});
const machine = (id: string, extra: Record<string, unknown>) => ({
  pk: "PROJECT#webapp",
  sk: `MACHINE#${id}`,
  kind: "oidc",
  issuer: GITHUB_ISSUER,
  claims: { repository: "acme/webapp", ref: "refs/heads/main" },
  stages: ["prod"],
  access: "read",
  createdAt: daysAgo(90),
  ...extra,
});
const use = (principal: string, stage: string, read?: number, write?: number) => ({
  pk: "USAGE#webapp",
  sk: `${principal}#${stage}`,
  principal,
  stage,
  ...(read !== undefined ? { lastRead: daysAgo(read), reads: 3 } : {}),
  ...(write !== undefined ? { lastWrite: daysAgo(write), writes: 1 } : {}),
});

function run(input: { members?: object[]; machines?: object[]; usage?: object[]; teamGrants?: never[] }) {
  const machines = (input.machines ?? []) as Record<string, unknown>[];
  const ents = buildEntitlements(
    {
      members: [{ pk: "PROJECT#webapp", sk: "MEMBER#owner@x.io", role: "owner", createdAt: daysAgo(400) }, ...(input.members ?? [])] as Record<string, unknown>[],
      machines,
      teamGrants: input.teamGrants ?? [],
      usage: (input.usage ?? []) as Record<string, unknown>[],
      stages: STAGES,
    },
    NOW,
  );
  return { ents, findings: analyze(ents, machines, { now: NOW, windowDays: 30, stages: STAGES }) };
}
const rules = (f: { rule: string; principal: string; stage?: string }[]) => f.map((x) => `${x.rule} ${x.principal}${x.stage ? ` ${x.stage}` : ""}`);

describe("CIEM findings", () => {
  it("never flags the owner", () => {
    expect(run({}).findings).toEqual([]);
  });

  it("flags a member who has not used any granted stage, high when prod is among them", () => {
    const { findings } = run({ members: [member("bob@x.io", ["dev", "prod"])], usage: [use("bob@x.io", "dev", 45)] });
    expect(findings[0]).toMatchObject({ rule: "inactive", severity: "high", fix: { kind: "removePrincipal" } });
  });

  it("flags only the unused stage when the member is otherwise active", () => {
    const { findings } = run({ members: [member("amy@x.io", ["dev", "prod"], { grantExpiresAt: daysAgo(-5) })], usage: [use("amy@x.io", "dev", 2)] });
    expect(rules(findings)).toEqual(["unused-stage amy@x.io prod"]);
    expect(findings[0].fix).toEqual({ kind: "removeStage", principal: "amy@x.io", via: "member", stage: "prod" });
  });

  it("gives fresh grants the benefit of the doubt", () => {
    const { findings } = run({ members: [member("new@x.io", ["dev"], { createdAt: daysAgo(3) })] });
    expect(findings).toEqual([]);
  });

  it("reports standing prod access for humans, not for time-boxed grants", () => {
    const standing = run({ members: [member("ops@x.io", ["prod"])], usage: [use("ops@x.io", "prod", 1)] });
    expect(rules(standing.findings)).toEqual(["standing-prod ops@x.io prod"]);
    const boxed = run({ members: [member("ops@x.io", ["prod"], { grantExpiresAt: daysAgo(-1) })], usage: [use("ops@x.io", "prod", 1)] });
    expect(boxed.findings).toEqual([]);
  });

  it("reports expired grants as cleanup, not as access", () => {
    const { ents, findings } = run({ members: [member("old@x.io", ["prod"], { grantExpiresAt: daysAgo(1) })] });
    expect(ents.find((e) => e.principal === "old@x.io")?.expired).toBe(true);
    expect(rules(findings)).toEqual(["expired-grant old@x.io"]);
  });

  it("downgrades machines that never write", () => {
    const { findings } = run({
      machines: [machine("ci", { access: "write" })],
      usage: [use("machine:webapp/ci", "prod", 1)],
    });
    expect(findings.map((f) => f.rule)).toContain("unused-write");
    expect(findings.find((f) => f.rule === "unused-write")?.fix).toEqual({ kind: "downgrade", principal: "machine:webapp/ci", via: "binding" });
  });

  it("flags GitHub bindings that admit any branch into prod", () => {
    const { findings } = run({
      machines: [machine("ci", { claims: { repository: "acme/webapp" } })],
      usage: [use("machine:webapp/ci", "prod", 1)],
    });
    expect(findings[0]).toMatchObject({ rule: "any-branch", severity: "high" });
    const pinned = run({
      machines: [machine("ci", { claims: { sub: "repo:acme/webapp:environment:production" } })],
      usage: [use("machine:webapp/ci", "prod", 1)],
    });
    expect(pinned.findings.map((f) => f.rule)).not.toContain("any-branch");
  });

  it("flags wildcard prod bindings and all-stage bindings", () => {
    const { findings } = run({
      machines: [machine("ci", { claims: { repository: "acme/webapp", ref: "refs/heads/*" }, stages: STAGES })],
      usage: STAGES.map((s) => use("machine:webapp/ci", s, 1)),
    });
    expect(findings.map((f) => f.rule).sort()).toEqual(["all-stages", "wildcard-prod"]);
  });

  it("does not offer a fix for team-derived access", () => {
    const ents = buildEntitlements(
      { members: [], machines: [], usage: [], stages: STAGES, teamGrants: [{ team: "ops", stages: ["prod"], grantedAt: daysAgo(90), members: ["t@x.io"] }] },
      NOW,
    );
    const [f] = analyze(ents, [], { now: NOW, stages: STAGES });
    expect(f).toMatchObject({ rule: "inactive", via: "team:ops" });
    expect(f.fix).toBeUndefined();
  });

  it("computes permission utilization", () => {
    const { ents } = run({ members: [member("amy@x.io", ["dev", "prod"])], usage: [use("amy@x.io", "dev", 2)] });
    expect(utilization(ents, 30, NOW)).toEqual({ granted: 2, used: 1, ratio: 0.5 });
  });
});

// ---- enforcement -------------------------------------------------------------

describe("time-boxed grants", () => {
  afterEach(() => vi.restoreAllMocks());

  it("stop granting at their deadline", async () => {
    expect(grantExpired({ grantExpiresAt: new Date(Date.now() - 1000).toISOString() })).toBe(true);
    expect(grantExpired({ grantExpiresAt: new Date(Date.now() + 60_000).toISOString() })).toBe(false);
    expect(grantExpired({})).toBe(false);
    vi.spyOn(DynamoDBDocumentClient.prototype, "send").mockImplementation(
      async () => ({ Item: { role: "member", stages: ["prod"], grantExpiresAt: new Date(Date.now() - 1000).toISOString() } }) as never,
    );
    expect(await canAccess("amy@x.io", "webapp", "prod")).toBe(false);
  });
});

describe("runner tokens", () => {
  const SECRET = "s";
  const claims = requirePrincipal(
    { headers: { authorization: `Bearer ${issueRunner({ prj: "webapp", run: "a".repeat(32), rev: "n1", src: "arn", act: "amy@x.io" }, SECRET)}` } },
    SECRET,
  );
  let run: Record<string, unknown> | undefined;

  beforeEach(() => {
    process.env.FEATURES = JSON.stringify({ cloudRunner: true });
    process.env.RUN_TABLE = "runs";
    run = { runId: "a".repeat(32), nonce: "n1", project: "webapp", stage: "prod", deadline: Math.floor(Date.now() / 1000) + 600 };
    vi.spyOn(DynamoDBDocumentClient.prototype, "send").mockImplementation(async () => ({ Item: run }) as never);
  });
  afterEach(() => vi.restoreAllMocks());

  it("read only the run's own project and stage", async () => {
    expect(claims.sub).toBe(`runner:${"a".repeat(32)}`);
    expect(await authorize(claims, "webapp", "prod", "read")).toBe(true);
    expect(await authorize(claims, "webapp", "prod", "write")).toBe(false);
    expect(await authorize(claims, "webapp", "dev", "read")).toBe(false);
    expect(await authorize(claims, "other", "prod", "read")).toBe(false);
  });

  it("die with the run's deadline, nonce, or the feature flag", async () => {
    run!.deadline = Math.floor(Date.now() / 1000) - 1;
    expect(await authorize(claims, "webapp", "prod", "read")).toBe(false);
    run!.deadline = Math.floor(Date.now() / 1000) + 600;
    run!.nonce = "other";
    expect(await authorize(claims, "webapp", "prod", "read")).toBe(false);
    run!.nonce = "n1";
    process.env.FEATURES = "{}";
    expect(await authorize(claims, "webapp", "prod", "read")).toBe(false);
  });
});

describe("audit record", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env.AUDIT_TABLE;
  });
  const claims = { sub: "runner:abc", typ: "machine" as const, iat: 0, exp: 0, prj: "webapp", mid: "@runner", rev: "n" };

  it("is a no-op without an audit table", async () => {
    const send = vi.spyOn(DynamoDBDocumentClient.prototype, "send");
    await record(null, { claims, project: "webapp", stage: "prod", action: "decrypt" });
    expect(send).not.toHaveBeenCalled();
  });

  it("writes the event and rolls usage up under the acting human", async () => {
    process.env.AUDIT_TABLE = "audit";
    const send = vi.spyOn(DynamoDBDocumentClient.prototype, "send").mockResolvedValue({} as never);
    await record(null, { claims, project: "webapp", stage: "prod", action: "decrypt", actor: "amy@x.io" });
    const input = (send.mock.calls[0][0] as { input: { TransactItems: { Put?: { Item: Record<string, unknown> }; Update?: { Key: unknown; UpdateExpression: string } }[] } }).input;
    expect(input.TransactItems[0].Put!.Item).toMatchObject({ principal: "runner:abc", kind: "runner", actor: "amy@x.io", action: "decrypt" });
    expect(input.TransactItems[1].Update!.Key).toEqual({ pk: "USAGE#webapp", sk: "amy@x.io#prod" });
    expect(input.TransactItems[1].Update!.UpdateExpression).toContain("lastRead");
  });

  it("propagates a failed write, so the vault call fails closed", async () => {
    process.env.AUDIT_TABLE = "audit";
    vi.spyOn(DynamoDBDocumentClient.prototype, "send").mockRejectedValue(new Error("throttled") as never);
    await expect(record(null, { claims, project: "webapp", stage: "prod", action: "decrypt" })).rejects.toThrow("throttled");
  });
});
