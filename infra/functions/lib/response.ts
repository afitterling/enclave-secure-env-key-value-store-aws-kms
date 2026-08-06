import type { APIGatewayProxyResultV2 } from "aws-lambda";

const CORS = {
  "content-type": "application/json",
  "access-control-allow-origin": "*",
  // Responses can carry a JWT or a plaintext data key — never let a shared
  // cache or the browser store them.
  "cache-control": "no-store",
};

export function json(statusCode: number, body: unknown): APIGatewayProxyResultV2 {
  return { statusCode, headers: CORS, body: JSON.stringify(body) };
}

export const ok = (body: unknown) => json(200, body);
export const badRequest = (msg: string) => json(400, { error: msg });
export const unauthorized = (msg = "unauthorized") => json(401, { error: msg });
export const forbidden = (msg = "forbidden") => json(403, { error: msg });
export const serverError = (msg = "internal error") => json(500, { error: msg });

/** Parse a JSON body that may be base64-encoded by API Gateway. Returns {} for
 * a missing or malformed body so handlers surface a clean 400 (via their own
 * required-field checks) instead of throwing into a CORS-less 502. */
export function parseBody<T = Record<string, unknown>>(event: {
  body?: string | null;
  isBase64Encoded?: boolean;
}): T {
  if (!event.body) return {} as T;
  const raw = event.isBase64Encoded
    ? Buffer.from(event.body, "base64").toString("utf8")
    : event.body;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return {} as T;
  }
}
