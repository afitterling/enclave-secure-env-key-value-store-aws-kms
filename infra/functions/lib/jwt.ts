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
  sub: string; // user email (normalized)
  iat: number;
  exp: number;
  iss?: string;
  aud?: string;
}

export function issue(email: string, secret: string, ttlSeconds = 3600): string {
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = b64url(
    JSON.stringify({ sub: email, iat: now, exp: now + ttlSeconds, iss: ISS, aud: AUD }),
  );
  const sig = sign(`${header}.${payload}`, secret);
  return `${header}.${payload}.${sig}`;
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
  return claims;
}

/** Extract + verify a Bearer token from an API Gateway v2 event. */
export function requireAuth(
  event: { headers?: Record<string, string | undefined> },
  secret: string,
): Claims {
  const headers = event.headers ?? {};
  const header = headers.authorization ?? headers.Authorization ?? "";
  const [scheme, token] = header.split(" ");
  if (scheme !== "Bearer" || !token) throw new Error("missing bearer token");
  return verify(token, secret);
}
