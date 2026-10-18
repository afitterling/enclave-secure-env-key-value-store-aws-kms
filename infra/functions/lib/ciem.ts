import { GITHUB_ISSUER } from "./machines.js";

/**
 * Entitlement analysis (enterprise `ciem` feature). Pure: admin/ciem.ts reads
 * the project's grants and usage rollups and hands them here, which keeps the
 * rules testable without DynamoDB.
 *
 * An entitlement is one path by which a principal reaches stages of a project:
 * ownership, a direct membership, a team grant, or a machine binding. The same
 * human can hold several (direct + via a team) and each is reported, because
 * each has to be removed separately.
 *
 * Findings compare what is granted with what is used inside a look-back window
 * (CIEM_UNUSED_DAYS, default 30), plus static checks on machine bindings that
 * are risky regardless of use. Each finding names a concrete fix the web UI can
 * apply through the existing member/binding endpoints.
 */

export type Severity = "high" | "medium" | "low";

export interface StageUsage {
  lastRead?: string;
  lastWrite?: string;
  reads: number;
  writes: number;
}

export interface Entitlement {
  principal: string; // email, or machine:<project>/<id>
  kind: "human" | "machine";
  via: string; // "owner" | "member" | "binding" | "team:<t>"
  stages: string[];
  access: "read" | "write";
  grantedAt?: string;
  grantExpiresAt?: string;
  expired: boolean;
  usage: Record<string, StageUsage>;
  lastUsed?: string;
}

export type Fix =
  | { kind: "removeStage"; principal: string; via: string; stage: string }
  | { kind: "removePrincipal"; principal: string; via: string }
  | { kind: "downgrade"; principal: string; via: string }
  | { kind: "timebox"; principal: string; via: string };

export interface Finding {
  id: string;
  rule: string;
  severity: Severity;
  principal: string;
  via: string;
  stage?: string;
  title: string;
  detail: string;
  fix?: Fix;
}

export interface GrantInput {
  members: Record<string, unknown>[]; // MEMBER# items
  machines: Record<string, unknown>[]; // MACHINE# items
  teamGrants: { team: string; stages: string[]; grantedAt?: string; members: string[] }[];
  usage: Record<string, unknown>[]; // USAGE# rollup items
  stages: string[];
}

const PROD = "prod";
const DAY = 86_400_000;

const latest = (...dates: (string | undefined)[]) =>
  dates.filter((d): d is string => !!d).sort().at(-1);

export function buildEntitlements(input: GrantInput, now = Date.now()): Entitlement[] {
  const usageBy = new Map<string, Record<string, StageUsage>>();
  for (const u of input.usage) {
    const principal = u.principal as string;
    const stage = u.stage as string;
    const per = usageBy.get(principal) ?? {};
    per[stage] = {
      lastRead: u.lastRead as string | undefined,
      lastWrite: u.lastWrite as string | undefined,
      reads: Number(u.reads ?? 0),
      writes: Number(u.writes ?? 0),
    };
    usageBy.set(principal, per);
  }

  const out: Entitlement[] = [];
  const push = (e: Omit<Entitlement, "usage" | "lastUsed" | "expired">) => {
    const all = usageBy.get(e.principal) ?? {};
    const usage = Object.fromEntries(e.stages.filter((s) => all[s]).map((s) => [s, all[s]]));
    const lastUsed = latest(...Object.values(usage).flatMap((u) => [u.lastRead, u.lastWrite]));
    const expired = !!e.grantExpiresAt && Date.parse(e.grantExpiresAt) <= now;
    out.push({ ...e, usage, lastUsed, expired });
  };

  for (const m of input.members) {
    const owner = m.role === "owner";
    push({
      principal: (m.sk as string).slice("MEMBER#".length),
      kind: "human",
      via: owner ? "owner" : "member",
      stages: owner ? input.stages : ((m.stages as string[]) ?? []),
      access: "write",
      grantedAt: m.createdAt as string | undefined,
      grantExpiresAt: owner ? undefined : (m.grantExpiresAt as string | undefined),
    });
  }
  for (const g of input.teamGrants) {
    for (const email of g.members) {
      push({
        principal: email,
        kind: "human",
        via: `team:${g.team}`,
        stages: g.stages,
        access: "write",
        grantedAt: g.grantedAt,
      });
    }
  }
  for (const b of input.machines) {
    const id = (b.sk as string).slice("MACHINE#".length);
    const project = (b.pk as string).slice("PROJECT#".length);
    push({
      principal: `machine:${project}/${id}`,
      kind: "machine",
      via: "binding",
      stages: (b.stages as string[]) ?? [],
      access: b.access === "write" ? "write" : "read",
      grantedAt: b.createdAt as string | undefined,
      grantExpiresAt: b.grantExpiresAt as string | undefined,
    });
  }
  return out;
}

/** Was this granted long enough ago that "unused" means something? */
function settled(e: Entitlement, windowMs: number, now: number) {
  return !e.grantedAt || now - Date.parse(e.grantedAt) >= windowMs;
}

const usedSince = (u: StageUsage | undefined, since: number, kind: "any" | "write" = "any") => {
  if (!u) return false;
  const stamps = kind === "write" ? [u.lastWrite] : [u.lastRead, u.lastWrite];
  return stamps.some((t) => !!t && Date.parse(t) >= since);
};

export function analyze(
  entitlements: Entitlement[],
  machines: Record<string, unknown>[],
  opts: { now?: number; windowDays?: number; stages?: string[] } = {},
): Finding[] {
  const now = opts.now ?? Date.now();
  const allStages = opts.stages ?? ["dev", "staging", "prod", "personal"];
  const windowDays = opts.windowDays ?? 30;
  const windowMs = windowDays * DAY;
  const since = now - windowMs;
  const findings: Finding[] = [];
  const add = (f: Omit<Finding, "id">) =>
    findings.push({ id: `${f.rule}:${f.principal}:${f.via}:${f.stage ?? ""}`, ...f });

  for (const e of entitlements) {
    if (e.via === "owner") continue; // ownership is the project, not a grant to prune

    if (e.expired) {
      add({
        rule: "expired-grant",
        severity: "low",
        principal: e.principal,
        via: e.via,
        title: "Expired grant still on file",
        detail: `Expired ${e.grantExpiresAt}. It no longer grants access; remove it to keep the list honest.`,
        fix: e.via.startsWith("team:") ? undefined : { kind: "removePrincipal", principal: e.principal, via: e.via },
      });
      continue;
    }

    const prod = e.stages.includes(PROD);
    const anyUse = e.stages.some((s) => usedSince(e.usage[s], since));
    if (settled(e, windowMs, now) && !anyUse) {
      add({
        rule: "inactive",
        severity: prod ? "high" : "medium",
        principal: e.principal,
        via: e.via,
        title: `No use in ${windowDays} days`,
        detail: `Holds ${e.stages.join(", ")} but has not read or written any of them${
          e.lastUsed ? ` since ${e.lastUsed.slice(0, 10)}` : " at all"
        }.`,
        fix: e.via.startsWith("team:") ? undefined : { kind: "removePrincipal", principal: e.principal, via: e.via },
      });
      continue; // per-stage findings would just repeat this one
    }

    if (settled(e, windowMs, now)) {
      for (const stage of e.stages) {
        if (usedSince(e.usage[stage], since)) continue;
        add({
          rule: "unused-stage",
          severity: stage === PROD ? "high" : "medium",
          principal: e.principal,
          via: e.via,
          stage,
          title: `${stage} granted, unused for ${windowDays} days`,
          detail: `Active on other stages, but not on ${stage}. Removing it shrinks the blast radius.`,
          fix: e.via.startsWith("team:")
            ? undefined
            : { kind: "removeStage", principal: e.principal, via: e.via, stage },
        });
      }
    }

    if (e.kind === "machine" && e.access === "write" && settled(e, windowMs, now)) {
      const wrote = e.stages.some((s) => usedSince(e.usage[s], since, "write"));
      if (!wrote) {
        add({
          rule: "unused-write",
          severity: prod ? "high" : "medium",
          principal: e.principal,
          via: e.via,
          title: "Write access never used",
          detail: `Only reads in the last ${windowDays} days. A read-only binding cannot overwrite or delete env files.`,
          fix: { kind: "downgrade", principal: e.principal, via: e.via },
        });
      }
    }

    if (e.kind === "human" && prod && !e.grantExpiresAt && !e.via.startsWith("team:")) {
      add({
        rule: "standing-prod",
        severity: "low",
        principal: e.principal,
        via: e.via,
        stage: PROD,
        title: "Standing prod access",
        detail: "No expiry. Time-boxed grants (just-in-time access) end on their own.",
        fix: { kind: "timebox", principal: e.principal, via: e.via },
      });
    }
  }

  // Static checks on how machine bindings are written.
  for (const b of machines) {
    const id = (b.sk as string).slice("MACHINE#".length);
    const project = (b.pk as string).slice("PROJECT#".length);
    const principal = `machine:${project}/${id}`;
    const stages = (b.stages as string[]) ?? [];
    const claims = (b.claims as Record<string, string>) ?? {};
    const prod = stages.includes(PROD);

    if (b.kind === "oidc" && b.issuer === GITHUB_ISSUER) {
      const sub = claims.sub ?? "";
      const pinsRef = !!claims.ref || !!claims.environment || /:(ref|environment):[^*]+$/.test(sub);
      if (!pinsRef) {
        add({
          rule: "any-branch",
          severity: prod ? "high" : "medium",
          principal,
          via: "binding",
          title: "Any branch or pull request can log in",
          detail:
            "The binding does not constrain ref or environment, so a workflow on any branch of the repository — including one pushed by any collaborator — gets these secrets. Pin ref (e.g. refs/heads/main) or a protected environment.",
        });
      }
    }

    const wild = Object.entries(claims).filter(([, v]) => v.includes("*"));
    if (prod && wild.length > 0) {
      add({
        rule: "wildcard-prod",
        severity: "medium",
        principal,
        via: "binding",
        stage: PROD,
        title: "Wildcard subject on a prod binding",
        detail: `Pattern${wild.length > 1 ? "s" : ""} ${wild.map(([k, v]) => `${k}=${v}`).join(", ")} admit more than one workload into prod.`,
      });
    }

    if (stages.length > 1 && allStages.every((s) => stages.includes(s))) {
      add({
        rule: "all-stages",
        severity: "low",
        principal,
        via: "binding",
        title: "Bound to every stage",
        detail: "One workload rarely needs dev and prod at once. Separate bindings per stage contain a compromise.",
      });
    }
  }

  const order: Record<Severity, number> = { high: 0, medium: 1, low: 2 };
  return findings.sort((a, b) => order[a.severity] - order[b.severity] || a.principal.localeCompare(b.principal));
}

/** Share of granted (principal, stage) pairs actually used in the window. */
export function utilization(entitlements: Entitlement[], windowDays = 30, now = Date.now()) {
  const since = now - windowDays * DAY;
  let granted = 0;
  let used = 0;
  for (const e of entitlements) {
    if (e.via === "owner" || e.expired) continue;
    for (const s of e.stages) {
      granted++;
      if (usedSince(e.usage[s], since)) used++;
    }
  }
  return { granted, used, ratio: granted ? used / granted : 1 };
}
