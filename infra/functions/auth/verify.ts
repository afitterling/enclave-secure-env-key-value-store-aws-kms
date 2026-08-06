import { createHash, timingSafeEqual } from "node:crypto";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, UpdateCommand, DeleteCommand } from "@aws-sdk/lib-dynamodb";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { normalizeEmail, permissionsFor } from "../lib/access.js";
import { issue } from "../lib/jwt.js";
import { ok, badRequest, unauthorized, parseBody } from "../lib/response.js";

const MAX_ATTEMPTS = 5;

const ddb = DynamoDBDocumentClient.from(
  new DynamoDBClient({ region: process.env.ENCLAVE_REGION }),
);

const hashCode = (email: string, code: string) =>
  createHash("sha256").update(`${email}:${code}`).digest("hex");

export async function handler(event: APIGatewayProxyEventV2) {
  const { email, code } = parseBody<{ email?: string; code?: string }>(event);
  if (!email || !code) return badRequest("email and code are required");
  const normalized = normalizeEmail(email);
  const now = Math.floor(Date.now() / 1000);
  const generic = unauthorized("invalid or expired code");

  // Atomically reserve one attempt BEFORE comparing. A separate read+write
  // (the previous shape) let concurrent requests all read attempts:0 and blow
  // past MAX_ATTEMPTS — the whole 6-digit space became guessable per code.
  // The conditional update makes each guess cost exactly one of five slots.
  let item;
  try {
    const out = await ddb.send(
      new UpdateCommand({
        TableName: process.env.OTP_TABLE,
        Key: { email: normalized },
        UpdateExpression: "SET attempts = if_not_exists(attempts, :z) + :one",
        ConditionExpression:
          "attribute_exists(email) AND expiresAt > :now AND if_not_exists(attempts, :z) < :max",
        ExpressionAttributeValues: { ":z": 0, ":one": 1, ":now": now, ":max": MAX_ATTEMPTS },
        ReturnValues: "ALL_NEW",
      }),
    );
    item = out.Attributes!;
  } catch (err: unknown) {
    // No such code, expired, or attempts exhausted — all indistinguishable.
    if ((err as { name?: string }).name === "ConditionalCheckFailedException") return generic;
    throw err;
  }

  const expected = Buffer.from(item.codeHash as string);
  const provided = Buffer.from(hashCode(normalized, code));
  const matches = expected.length === provided.length && timingSafeEqual(expected, provided);
  if (!matches) return generic;

  // Single-use: burn the code.
  await ddb.send(
    new DeleteCommand({ TableName: process.env.OTP_TABLE, Key: { email: normalized } }),
  );

  const token = issue(normalized, process.env.JWT_SIGNING_KEY!);
  return ok({ token, email: normalized, access: await permissionsFor(normalized) });
}
