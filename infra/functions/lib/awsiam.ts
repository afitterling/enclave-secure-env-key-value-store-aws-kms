/**
 * AWS IAM workload authentication, the way Vault's aws auth method does it:
 * the workload signs an `sts:GetCallerIdentity` request with its own
 * credentials (task role, Lambda role, instance profile, CI role) but does not
 * send it. We forward it to STS unmodified; STS checks the signature and tells
 * us who signed it. No AWS permission is needed on our side, and the
 * workload's credentials never leave it — a signed request is not a credential.
 *
 * Replay protection: the request must carry SERVER_ID_HEADER = our audience,
 * and that header must be covered by the SigV4 signature, so a request signed
 * for some other enclave deployment (or any other Vault-style verifier) cannot
 * be replayed here. STS itself rejects signatures older than 15 minutes.
 */

export const SERVER_ID_HEADER = "x-enclave-server-id";

const STS_BODY = "Action=GetCallerIdentity&Version=2011-06-15";
const REGION = /^[a-z]{2}(-gov|-iso[a-z]?)?-[a-z]+-\d$/;

// Headers we pass through to STS. Anything else the caller sent is dropped;
// content-length is recomputed by fetch from the identical body.
const FORWARD = ["authorization", "content-type", "x-amz-date", "x-amz-security-token", SERVER_ID_HEADER];

export class AwsAuthError extends Error {}

export interface SignedStsRequest {
  method?: unknown;
  url?: unknown;
  headers?: unknown;
  body?: unknown; // base64
}

function stsUrlOk(raw: string): boolean {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  if (u.protocol !== "https:" || u.port || u.username || u.search || u.hash || u.pathname !== "/") {
    return false;
  }
  if (u.hostname === "sts.amazonaws.com") return true;
  const m = /^sts\.([a-z0-9-]+)\.amazonaws\.com$/.exec(u.hostname);
  return !!m && REGION.test(m[1]);
}

function signedHeaders(authorization: string): string[] {
  const m = /SignedHeaders=([^,\s]+)/.exec(authorization);
  return m ? m[1].toLowerCase().split(";") : [];
}

/** Validate the request shape, forward it to STS, and return the caller ARN. */
export async function verifySignedStsRequest(
  req: SignedStsRequest,
  audience: string,
): Promise<{ arn: string; account: string; userId: string }> {
  if (req.method !== undefined && req.method !== "POST") throw new AwsAuthError("method must be POST");
  if (typeof req.url !== "string" || !stsUrlOk(req.url)) throw new AwsAuthError("not an STS endpoint");
  if (typeof req.body !== "string") throw new AwsAuthError("body is required");
  const body = Buffer.from(req.body, "base64").toString("utf8");
  if (body !== STS_BODY) throw new AwsAuthError("only GetCallerIdentity may be signed");

  if (!req.headers || typeof req.headers !== "object" || Array.isArray(req.headers)) {
    throw new AwsAuthError("headers are required");
  }
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers as Record<string, unknown>)) {
    const name = k.toLowerCase();
    if (FORWARD.includes(name) && typeof v === "string") headers[name] = v;
  }

  const auth = headers.authorization ?? "";
  if (!auth.startsWith("AWS4-HMAC-SHA256 ")) throw new AwsAuthError("not a SigV4 request");
  if (!headers["x-amz-date"]) throw new AwsAuthError("x-amz-date is required");
  if (headers[SERVER_ID_HEADER] !== audience) throw new AwsAuthError("server id mismatch");
  const signed = signedHeaders(auth);
  if (!signed.includes(SERVER_ID_HEADER) || !signed.includes("host")) {
    throw new AwsAuthError(`${SERVER_ID_HEADER} must be a signed header`);
  }

  const res = await fetch(req.url, {
    method: "POST",
    headers,
    body,
    redirect: "error",
    signal: AbortSignal.timeout(5000),
  });
  const text = await res.text();
  if (!res.ok) throw new AwsAuthError(`STS rejected the request (${res.status})`);

  const pick = (tag: string) => new RegExp(`<${tag}>([^<]+)</${tag}>`).exec(text)?.[1];
  const arn = pick("Arn");
  const account = pick("Account");
  const userId = pick("UserId");
  if (!arn || !account || !userId) throw new AwsAuthError("unexpected STS response");
  return { arn, account, userId };
}
