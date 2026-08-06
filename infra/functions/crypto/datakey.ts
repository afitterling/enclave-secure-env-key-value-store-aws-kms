import { KMSClient, GenerateDataKeyCommand, DecryptCommand } from "@aws-sdk/client-kms";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { canAccess } from "../lib/access.js";
import { requireAuth } from "../lib/jwt.js";
import { ok, badRequest, unauthorized, forbidden, parseBody } from "../lib/response.js";

/**
 * Envelope-encryption broker. The master key never leaves KMS.
 *
 *  op="generate": returns a fresh AES-256 data key, both as plaintext (for the
 *                 CLI to encrypt with, in-memory only) and as a KMS ciphertext
 *                 blob (stored inside the uploaded file's header).
 *  op="decrypt":  unwraps a previously generated ciphertext blob so another
 *                 device can recover the plaintext key and decrypt.
 *
 * The (project, stage) pair is bound to the ciphertext via a KMS encryption
 * context, so a blob minted for stage X cannot be unwrapped while claiming
 * access to stage Y.
 */

const kms = new KMSClient({ region: process.env.ENCLAVE_REGION });

interface Body {
  op?: "generate" | "decrypt";
  project?: string;
  stage?: string;
  ciphertext?: string; // base64, required for op=decrypt
}

// Same rule presign uses — reject non-string / structured values so they can't
// diverge the KMS encryption context from the string form used at generate.
const safeName = (name: unknown): name is string =>
  typeof name === "string" && /^[\w.@+-]+$/.test(name);

export async function handler(event: APIGatewayProxyEventV2) {
  let email: string;
  try {
    email = requireAuth(event, process.env.JWT_SIGNING_KEY!).sub;
  } catch {
    return unauthorized();
  }

  const { op, project, stage, ciphertext } = parseBody<Body>(event);
  if (!op || !project || !stage) return badRequest("op, project and stage are required");
  if (!safeName(project) || !safeName(stage)) return badRequest("invalid project/stage");
  if (!(await canAccess(email, project, stage))) return forbidden("no access to this project/stage");

  const encryptionContext = { project, stage, app: "enclave-envoy" };

  if (op === "generate") {
    const out = await kms.send(
      new GenerateDataKeyCommand({
        KeyId: process.env.KMS_KEY_ID,
        KeySpec: "AES_256",
        EncryptionContext: encryptionContext,
      }),
    );
    return ok({
      plaintext: Buffer.from(out.Plaintext!).toString("base64"),
      ciphertext: Buffer.from(out.CiphertextBlob!).toString("base64"),
    });
  }

  if (op === "decrypt") {
    if (!ciphertext) return badRequest("ciphertext is required for decrypt");
    const out = await kms.send(
      new DecryptCommand({
        KeyId: process.env.KMS_KEY_ID, // pin the key; don't let the blob select it
        CiphertextBlob: Buffer.from(ciphertext, "base64"),
        EncryptionContext: encryptionContext, // must match what generate used
      }),
    );
    return ok({ plaintext: Buffer.from(out.Plaintext!).toString("base64") });
  }

  return badRequest("op must be 'generate' or 'decrypt'");
}
