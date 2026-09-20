import { timingSafeEqual } from "node:crypto";
import { forbidden } from "./response.js";

/**
 * Proof that a request arrived through CloudFront.
 *
 * AWS WAF cannot attach to an API Gateway HTTP API, so the edge Web ACL lives
 * on the CloudFront distribution and the API is served from it under /api.
 * That only helps if the raw execute-api URL cannot be used to walk around it,
 * hence this check: CloudFront injects a secret header on the API origin and
 * every handler rejects a request that does not carry it.
 *
 * An unset EDGE_ORIGIN_TOKEN disables the check. That is deliberate — it keeps
 * stages that predate the token working, and lets it be rolled out one stage at
 * a time with `sst secret set EdgeOriginToken`.
 */
export function edgeRejection(event: {
  headers?: Record<string, string | undefined>;
}): ReturnType<typeof forbidden> | null {
  const expected = process.env.EDGE_ORIGIN_TOKEN;
  if (!expected) return null; // not enforced on this stage

  // API Gateway v2 lowercases header names.
  const presented = event.headers?.["x-edge-origin-token"];
  if (!presented) return forbidden();

  const a = Buffer.from(presented);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return forbidden();
  return null;
}
