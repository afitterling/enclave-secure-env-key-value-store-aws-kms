import {
  GetObjectCommand,
  PutObjectCommand,
  DeleteObjectCommand,
  ListObjectsV2Command,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { authorize } from "../lib/access.js";
import { featureEnabled } from "../lib/features.js";
import { s3ForStage } from "../lib/assume.js";
import { requirePrincipal, type Claims } from "../lib/jwt.js";
import { ok, badRequest, unauthorized, forbidden, parseBody } from "../lib/response.js";
import { edgeRejection } from "../lib/edge.js";

/**
 * Brokers S3 access for the CLI and web UI. Validates the user against the
 * DynamoDB access map, assumes the per-stage role (whose permissions the bucket
 * policy scopes to this stage's `<project>/<stage>/<file>` keys), and returns a
 * short-lived presigned URL. Enforces the `project-id/stage/file` key layout
 * server-side.
 */

const PRESIGN_TTL = 300; // seconds

interface Body {
  op?: "upload" | "download" | "delete" | "list";
  project?: string;
  stage?: string;
  file?: string; // basename; required for upload/download/delete
}

// Disallow path traversal / nested prefixes in the filename component.
const safeName = (name: string) => /^[\w.@+-]+$/.test(name);

export async function handler(event: APIGatewayProxyEventV2) {
  // Reject anything that did not come through CloudFront (see lib/edge.ts).
  const blocked = edgeRejection(event);
  if (blocked) return blocked;

  let claims: Claims;
  try {
    claims = requirePrincipal(event, process.env.JWT_SIGNING_KEY!);
  } catch {
    return unauthorized();
  }

  const { op, project, stage, file } = parseBody<Body>(event);
  if (!op || !project || !stage) return badRequest("op, project and stage are required");
  if (!safeName(project) || !safeName(stage)) return badRequest("invalid project/stage");
  const action = op === "upload" || op === "delete" ? "write" : "read";
  if (!(await authorize(claims, project, stage, action))) {
    return forbidden("no access to this project/stage");
  }

  const bucket = process.env.BUCKET!;
  const prefix = `${project}/${stage}/`;
  // The STS session name shows up in CloudTrail for every S3 call made with
  // the presigned URL, so it names the principal: an email or machine:<p>/<id>.
  const s3 = await s3ForStage(stage, claims.sub);

  if (op === "list") {
    const out = await s3.send(new ListObjectsV2Command({ Bucket: bucket, Prefix: prefix }));
    const files = (out.Contents ?? [])
      .map((o) => o.Key!.slice(prefix.length))
      .filter(Boolean);
    return ok({ prefix, files });
  }

  if (!file || !safeName(file)) return badRequest("a valid file name is required");
  const Key = `${prefix}${file}`;

  if (op === "upload") {
    const url = await getSignedUrl(s3, new PutObjectCommand({ Bucket: bucket, Key }), {
      expiresIn: PRESIGN_TTL,
    });
    return ok({ url, method: "PUT", key: Key, expiresIn: PRESIGN_TTL });
  }

  if (op === "download") {
    const url = await getSignedUrl(s3, new GetObjectCommand({ Bucket: bucket, Key }), {
      expiresIn: PRESIGN_TTL,
    });
    return ok({ url, method: "GET", key: Key, expiresIn: PRESIGN_TTL });
  }

  if (op === "delete") {
    if (!featureEnabled("fileDelete")) return forbidden("file deletion is not enabled");
    const url = await getSignedUrl(s3, new DeleteObjectCommand({ Bucket: bucket, Key }), {
      expiresIn: PRESIGN_TTL,
    });
    return ok({ url, method: "DELETE", key: Key, expiresIn: PRESIGN_TTL });
  }

  return badRequest("op must be 'upload', 'download', 'delete' or 'list'");
}
