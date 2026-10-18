import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Tiny dependency-free HS256 JWT implementation. Enough for short-lived session
 * tokens; swap for a vetted library (jose) if you need richer claims/validation.
 */

const ISS = "enclave-envoy";
const AUD = "enclave-envoy";

const b64url = (buf: Buffer | string) =>
  Buffer.from(buf).toString("base64url");

function sign(data: string, secret: string): string {
  return createHmac("sha256", secret).update(data).digest("base64url");
}

export interface Claims {
  sub: string; // user email (normalized), or machine:<project>/<identity>
  iat: number;
  exp: number;
  iss?: string;
  aud?: string;
  // Machine tokens only (see auth/workload.ts). A human token has none of these.
  typ?: "machine";
  prj?: string; // project the binding belongs to
  mid?: string; // binding (identity) id within the project
  rev?: string; // binding revision; a re-created binding invalidates old tokens
  src?: string; // who proved it: OIDC `sub` or the caller's AWS ARN (audit only)
}

export type MachineClaims = Required<Pick<Claims, "prj" | "mid" | "rev" | "src">>;

function encode(body: Record<string, unknown>, secret: string): string {
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = b64url(JSON.stringify(body));
  const sig = sign(`${header}.${payload}`, secret);
  return `${header}.${payload}.${sig}`;
}

export function issue(email: string, secret: string, ttlSeconds = 3600): string {
  const now = Math.floor(Date.now() / 1000);
  return encode({ sub: email, iat: now, exp: now + ttlSeconds, iss: ISS, aud: AUD }, secret);
}

/** Short-lived token for a workload that proved a machine-identity binding. */
export function issueMachine(m: MachineClaims, secret: string, ttlSeconds = 900): string {
  const now = Math.floor(Date.now() / 1000);
  return encode(
    {
      sub: `machine:${m.prj}/${m.mid}`,
      typ: "machine",
      ...m,
      iat: now,
      exp: now + ttlSeconds,
      iss: ISS,
      aud: AUD,
    },
    secret,
  );
}

/** Returns claims if valid+unexpired, otherwise throws.
 *
 * Note on algorithm confusion: `expected` is always recomputed as HS256, so a
 * forged `alg:none` or RS256 header fails the HMAC check regardless — we still
 * assert the header alg defensively, but the security does not depend on it. */
export function verify(token: string, secret: string): Claims {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("malformed token");
  const [header, payload, sig] = parts;

  const head = JSON.parse(Buffer.from(header, "base64url").toString("utf8")) as { alg?: string };
  if (head.alg !== "HS256") throw new Error("unexpected alg");

  const expected = sign(`${header}.${payload}`, secret);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) throw new Error("bad signature");

  const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Claims;
  const now = Math.floor(Date.now() / 1000);
  if (typeof claims.exp !== "number" || claims.exp <= now) throw new Error("token expired");
  if (claims.iss !== ISS || claims.aud !== AUD) throw new Error("bad issuer/audience");
  if (typeof claims.sub !== "string" || !claims.sub) throw new Error("bad subject");
  if (claims.typ !== undefined && claims.typ !== "machine") throw new Error("bad token type");
  if (
    claims.typ === "machine" &&
    ![claims.prj, claims.mid, claims.rev].every((v) => typeof v === "string" && v)
  ) {
    throw new Error("bad machine claims");
  }
  return claims;
}

/** Extract + verify a Bearer token (human or machine) from an API Gateway v2 event.
 * Only the vault endpoints (datakey, presign) accept machine tokens, and they
 * must then authorize through access.authorize(), which understands both. */
export function requirePrincipal(
  event: { headers?: Record<string, string | undefined> },
  secret: string,
): Claims {
  const headers = event.headers ?? {};
  const header = headers.authorization ?? headers.Authorization ?? "";
  const [scheme, token] = header.split(" ");
  if (scheme !== "Bearer" || !token) throw new Error("missing bearer token");
  return verify(token, secret);
}

/** Like requirePrincipal, but human sessions only. The default for every
 * endpoint: a machine `sub` is not an email and must never become a project
 * owner, an inviter, or anything else the admin routes key on. */
export function requireAuth(
  event: { headers?: Record<string, string | undefined> },
  secret: string,
): Claims {
  const claims = requirePrincipal(event, secret);
  if (claims.typ === "machine") throw new Error("machine tokens are not accepted here");
  return claims;
}
