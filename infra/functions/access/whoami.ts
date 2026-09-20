import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { permissionsFor } from "../lib/access.js";
import { requireAuth } from "../lib/jwt.js";
import { ok, unauthorized } from "../lib/response.js";
import { edgeRejection } from "../lib/edge.js";

/** Returns the authenticated user's full project/stage access map. */
export async function handler(event: APIGatewayProxyEventV2) {
  // Reject anything that did not come through CloudFront (see lib/edge.ts).
  const blocked = edgeRejection(event);
  if (blocked) return blocked;

  let claims;
  try {
    claims = requireAuth(event, process.env.JWT_SIGNING_KEY!);
  } catch {
    return unauthorized();
  }
  return ok({ email: claims.sub, access: await permissionsFor(claims.sub) });
}
