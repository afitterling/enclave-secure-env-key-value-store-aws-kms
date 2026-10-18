import { randomBytes } from "node:crypto";
import { validStages } from "./access.js";

/**
 * Machine identities: rules that bind a workload's own identity (an OIDC token
 * from GitHub Actions / GitLab / Kubernetes, or an AWS IAM role) to a project's
 * stages. Stored next to the human members, one item per binding:
 *
 *   PROJECT#<p> / MACHINE#<id>
 *     kind: "oidc" | "aws"
 *     oidc: issuer, audience?, claims { name: pattern }
 *     aws:  account, role
 *     stages[], access: "read" | "write", description?, rev, createdBy, createdAt
 *
 * `rev` is fresh on every write. Machine tokens carry it, and authorize()
 * compares it, so editing or re-creating a binding invalidates tokens minted
 * under the old rules instead of letting them run out their 15 minutes.
 *
 * Patterns: `*` matches any run of characters except `:`, so
 * `repo:acme/api:ref:refs/heads/*` is "any branch of acme/api", while
 * `repo:acme/*:ref:refs/heads/main` is "main of any acme repository".
 */

export const GITHUB_ISSUER = "https://token.actions.githubusercontent.com";

export type MachineAccess = "read" | "write";

export interface MachineBinding {
  id: string;
  kind: "oidc" | "aws";
  issuer?: string;
  audience?: string;
  claims?: Record<string, string>;
  account?: string;
  role?: string;
  stages: string[];
  access: MachineAccess;
  description?: string;
  rev: string;
  createdBy?: string;
  createdAt?: string;
}

const safeName = (name: string) => /^[\w.@+-]+$/.test(name);
const CLAIM_NAME = /^[A-Za-z_][\w.-]{0,63}$/;
const AWS_ACCOUNT = /^\d{12}$/;
const AWS_ROLE = /^[\w+=,.@-]{1,64}$/;

/** True when the host part of an https URL is a name, not a literal address
 * or a local-only name. Issuers are owner-supplied URLs the Lambda fetches. */
export function isPublicHttpsUrl(raw: string): boolean {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  if (u.protocol !== "https:" || u.username || u.password || u.port) return false;
  const host = u.hostname.toLowerCase();
  if (/^[\d.]+$/.test(host) || host.includes(":") || host.startsWith("[")) return false;
  if (!host.includes(".")) return false;
  return !/(^|\.)(localhost|local|internal|localdomain)$/.test(host);
}

/** Canonical issuer form: no trailing slash, no query/fragment. */
export function normalizeIssuer(raw: string): string {
  return raw.trim().replace(/\/+$/, "");
}

function patternToRegExp(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^:]*");
  return new RegExp(`^${escaped}$`);
}

export function matchesPattern(pattern: string, value: unknown): boolean {
  if (typeof value === "number" || typeof value === "boolean") value = String(value);
  if (typeof value !== "string") return false;
  return patternToRegExp(pattern).test(value);
}

/** Every constraint in the binding must match the verified token's claims. */
export function claimsMatch(constraints: Record<string, string>, claims: Record<string, unknown>) {
  const entries = Object.entries(constraints);
  return entries.length > 0 && entries.every(([name, pattern]) => matchesPattern(pattern, claims[name]));
}

/** Split an STS caller ARN into account + role. Only roles can be bound:
 * assumed-role sessions (ECS/Lambda/EC2/CI) and, for completeness, the role ARN. */
export function parseCallerArn(arn: string): { account: string; role: string; session?: string } | null {
  const assumed = /^arn:aws[\w-]*:sts::(\d{12}):assumed-role\/([^/]+)\/(.+)$/.exec(arn);
  if (assumed) return { account: assumed[1], role: assumed[2], session: assumed[3] };
  const role = /^arn:aws[\w-]*:iam::(\d{12}):role\/(?:.*\/)?([^/]+)$/.exec(arn);
  if (role) return { account: role[1], role: role[2] };
  return null;
}

/**
 * A constraint must pin an owner, not just shape. For GitHub that means a
 * literal `repo:<owner>/` on `sub` or `<owner>/` on `repository`, or a numeric
 * `repository_id` / `repository_owner_id`; anything less admits every
 * repository on github.com. Other issuers must constrain `sub` with a literal
 * prefix, since a shared issuer (gitlab.com, a cloud's K8s OIDC) has the same
 * problem.
 */
function pinsAnOwner(issuer: string, claims: Record<string, string>): boolean {
  if (issuer === GITHUB_ISSUER) {
    if (claims.sub && /^repo:[^*:/]+\//.test(claims.sub)) return true;
    if (claims.repository && /^[^*/]+\//.test(claims.repository)) return true;
    if (claims.repository_id && /^\d+$/.test(claims.repository_id)) return true;
    if (claims.repository_owner_id && /^\d+$/.test(claims.repository_owner_id)) return true;
    return false;
  }
  return typeof claims.sub === "string" && /^[^*]{3,}/.test(claims.sub);
}

export type ValidationResult = { ok: true; binding: Omit<MachineBinding, "rev" | "createdBy" | "createdAt"> } | { ok: false; error: string };

/** Validate an owner-submitted binding. Returns the canonical shape to store. */
export function validateBinding(body: Record<string, unknown>): ValidationResult {
  const fail = (error: string): ValidationResult => ({ ok: false, error });

  const id = typeof body.id === "string" ? body.id : "";
  if (!id || id.length > 64 || !safeName(id)) return fail("a valid identity id is required");

  const access = body.access ?? "read";
  if (access !== "read" && access !== "write") return fail("access must be 'read' or 'write'");

  if (!Array.isArray(body.stages)) return fail("stages must be a non-empty list");
  const wanted = [...new Set(body.stages)].filter((s): s is string => typeof s === "string");
  const valid = validStages();
  if (wanted.length === 0 || !wanted.every((s) => valid.includes(s))) {
    return fail(`stages must be a non-empty subset of ${valid.join(", ")}`);
  }
  const stages = valid.filter((s) => wanted.includes(s));

  let description: string | undefined;
  if (body.description !== undefined) {
    if (typeof body.description !== "string" || body.description.length > 200) {
      return fail("description must be a string of at most 200 characters");
    }
    description = body.description.trim() || undefined;
  }

  const base = { id, stages, access: access as MachineAccess, description };

  if (body.kind === "oidc") {
    const issuer = typeof body.issuer === "string" ? normalizeIssuer(body.issuer) : "";
    if (!isPublicHttpsUrl(issuer)) return fail("issuer must be a public https URL");
    let audience: string | undefined;
    if (body.audience !== undefined && body.audience !== "") {
      if (typeof body.audience !== "string" || body.audience.length > 256) {
        return fail("audience must be a string");
      }
      audience = body.audience;
    }
    const raw = body.claims;
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      return fail("claims must be an object of claim name -> pattern");
    }
    const claims: Record<string, string> = {};
    for (const [name, pattern] of Object.entries(raw as Record<string, unknown>)) {
      if (!CLAIM_NAME.test(name)) return fail(`invalid claim name '${name}'`);
      if (["iss", "aud", "exp", "nbf", "iat"].includes(name)) {
        return fail(`'${name}' is checked by the server and cannot be a constraint`);
      }
      if (typeof pattern !== "string" || !pattern || pattern.length > 256) {
        return fail(`claim '${name}' needs a non-empty string pattern`);
      }
      if (/^\**$/.test(pattern)) return fail(`claim '${name}' would match anything`);
      claims[name] = pattern;
    }
    if (Object.keys(claims).length === 0 || Object.keys(claims).length > 10) {
      return fail("between 1 and 10 claim constraints are required");
    }
    if (!pinsAnOwner(issuer, claims)) {
      return fail(
        issuer === GITHUB_ISSUER
          ? "a GitHub binding must pin the owner: sub 'repo:<owner>/…', repository '<owner>/…', or a numeric repository_id / repository_owner_id"
          : "an OIDC binding must constrain 'sub' with a literal prefix",
      );
    }
    return { ok: true, binding: { ...base, kind: "oidc", issuer, audience, claims } };
  }

  if (body.kind === "aws") {
    const account = typeof body.account === "string" ? body.account : "";
    const role = typeof body.role === "string" ? body.role : "";
    if (!AWS_ACCOUNT.test(account)) return fail("account must be a 12-digit AWS account id");
    if (!AWS_ROLE.test(role)) return fail("role must be an IAM role name (no wildcards, no path)");
    return { ok: true, binding: { ...base, kind: "aws", account, role } };
  }

  return fail("kind must be 'oidc' or 'aws'");
}

export const newRev = () => randomBytes(9).toString("base64url");

/** Public view of a stored item (strips the table keys). */
export function toBinding(item: Record<string, unknown>): MachineBinding {
  return {
    id: (item.sk as string).slice("MACHINE#".length),
    kind: item.kind as "oidc" | "aws",
    issuer: item.issuer as string | undefined,
    audience: item.audience as string | undefined,
    claims: item.claims as Record<string, string> | undefined,
    account: item.account as string | undefined,
    role: item.role as string | undefined,
    stages: (item.stages as string[]) ?? [],
    access: (item.access as MachineAccess) ?? "read",
    description: item.description as string | undefined,
    rev: item.rev as string,
    createdBy: item.createdBy as string | undefined,
    createdAt: item.createdAt as string | undefined,
  };
}
