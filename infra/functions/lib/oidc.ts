import { createPublicKey, verify as verifySignature, constants, type JsonWebKey } from "node:crypto";
import { isPublicHttpsUrl, normalizeIssuer } from "./machines.js";

/**
 * Verifies OIDC ID tokens from workload issuers (GitHub Actions, GitLab CI,
 * Kubernetes service-account tokens, ...) against the issuer's published JWKS.
 * Dependency-free like lib/jwt.ts: node:crypto imports JWKs directly.
 *
 * The issuer URL comes from a project owner, so every fetch is https-only,
 * name-based (no literal IPs), redirect-free, size-capped and time-boxed.
 *
 * JWKS are cached per issuer for 10 minutes. That is key material, not an
 * access decision — the binding itself is re-read from DynamoDB every time.
 */

const ALGS: Record<string, { hash: string; kty: string; pss?: boolean; ec?: boolean }> = {
  RS256: { hash: "sha256", kty: "RSA" },
  RS384: { hash: "sha384", kty: "RSA" },
  RS512: { hash: "sha512", kty: "RSA" },
  PS256: { hash: "sha256", kty: "RSA", pss: true },
  PS384: { hash: "sha384", kty: "RSA", pss: true },
  ES256: { hash: "sha256", kty: "EC", ec: true },
  ES384: { hash: "sha384", kty: "EC", ec: true },
};

const CLOCK_SKEW = 60; // seconds
const JWKS_TTL = 600_000; // ms
const MIN_REFETCH = 60_000; // ms; an unknown kid can't force a fetch per request
const MAX_BYTES = 256 * 1024;

interface Jwk extends JsonWebKey {
  kid?: string;
  alg?: string;
  use?: string;
}

const cache = new Map<string, { keys: Jwk[]; fetchedAt: number }>();

export class OidcError extends Error {}

async function fetchJson(url: string): Promise<unknown> {
  if (!isPublicHttpsUrl(url)) throw new OidcError(`refusing to fetch ${url}`);
  const res = await fetch(url, {
    redirect: "error",
    signal: AbortSignal.timeout(3000),
    headers: { accept: "application/json" },
  });
  if (!res.ok) throw new OidcError(`${url} answered ${res.status}`);
  const text = await res.text();
  if (text.length > MAX_BYTES) throw new OidcError(`${url} response too large`);
  return JSON.parse(text);
}

async function loadKeys(issuer: string, force = false): Promise<Jwk[]> {
  const hit = cache.get(issuer);
  const age = hit ? Date.now() - hit.fetchedAt : Infinity;
  if (hit && (age < JWKS_TTL && !force)) return hit.keys;
  if (hit && force && age < MIN_REFETCH) return hit.keys;

  const discovery = (await fetchJson(`${issuer}/.well-known/openid-configuration`)) as {
    issuer?: string;
    jwks_uri?: string;
  };
  if (!discovery.issuer || normalizeIssuer(discovery.issuer) !== issuer) {
    throw new OidcError("discovery document names a different issuer");
  }
  if (!discovery.jwks_uri) throw new OidcError("discovery document has no jwks_uri");
  const jwks = (await fetchJson(discovery.jwks_uri)) as { keys?: Jwk[] };
  const keys = Array.isArray(jwks.keys) ? jwks.keys : [];
  cache.set(issuer, { keys, fetchedAt: Date.now() });
  return keys;
}

function pickKey(keys: Jwk[], kid: string | undefined, kty: string): Jwk | undefined {
  const usable = keys.filter((k) => k.kty === kty && (!k.use || k.use === "sig"));
  if (kid) return usable.find((k) => k.kid === kid);
  return usable.length === 1 ? usable[0] : undefined;
}

const decodePart = (part: string) => JSON.parse(Buffer.from(part, "base64url").toString("utf8"));

/**
 * Verify `token` was issued by `issuer` for `audience` and is currently valid.
 * Returns the claims. Throws OidcError with a reason (for logs, not callers).
 */
export async function verifyOidcToken(
  token: string,
  issuerRaw: string,
  audience: string,
): Promise<Record<string, unknown>> {
  const issuer = normalizeIssuer(issuerRaw);
  if (typeof token !== "string" || token.length > 16_384) throw new OidcError("bad token");
  const parts = token.split(".");
  if (parts.length !== 3) throw new OidcError("malformed token");
  const [h, p, s] = parts;

  let header: { alg?: string; kid?: string };
  let claims: Record<string, unknown>;
  try {
    header = decodePart(h);
    claims = decodePart(p);
  } catch {
    throw new OidcError("undecodable token");
  }

  const alg = header.alg ? ALGS[header.alg] : undefined;
  if (!alg) throw new OidcError(`unsupported alg ${header.alg}`);

  let key = pickKey(await loadKeys(issuer), header.kid, alg.kty);
  if (!key) key = pickKey(await loadKeys(issuer, true), header.kid, alg.kty); // key rotation
  if (!key) throw new OidcError("no matching signing key");
  if (key.alg && key.alg !== header.alg) throw new OidcError("key/alg mismatch");

  const publicKey = createPublicKey({ key, format: "jwk" });
  const signature = Buffer.from(s, "base64url");
  const data = Buffer.from(`${h}.${p}`);
  const valid = verifySignature(
    alg.hash,
    data,
    alg.ec
      ? { key: publicKey, dsaEncoding: "ieee-p1363" }
      : alg.pss
        ? { key: publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST }
        : publicKey,
    signature,
  );
  if (!valid) throw new OidcError("bad signature");

  const now = Math.floor(Date.now() / 1000);
  if (typeof claims.iss !== "string" || normalizeIssuer(claims.iss) !== issuer) {
    throw new OidcError("issuer mismatch");
  }
  const aud = claims.aud;
  const audOk = Array.isArray(aud) ? aud.includes(audience) : aud === audience;
  if (!audOk) throw new OidcError("audience mismatch");
  if (typeof claims.exp !== "number" || claims.exp <= now - CLOCK_SKEW) throw new OidcError("expired");
  if (typeof claims.nbf === "number" && claims.nbf > now + CLOCK_SKEW) throw new OidcError("not yet valid");
  if (typeof claims.iat === "number" && claims.iat > now + CLOCK_SKEW) throw new OidcError("issued in the future");
  return claims;
}

/** Test hook: forget cached JWKS. */
export function _resetJwksCache() {
  cache.clear();
}
