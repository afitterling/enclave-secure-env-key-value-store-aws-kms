import { createHash, randomInt } from "node:crypto";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand } from "@aws-sdk/lib-dynamodb";
import { SESClient, SendEmailCommand } from "@aws-sdk/client-ses";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { isKnownUser, normalizeEmail } from "../lib/access.js";
import { ok, badRequest, parseBody } from "../lib/response.js";

const OTP_DIGITS = 6;
const TTL_SECONDS = 600; // code valid for 10 minutes
const RESEND_SECONDS = 60; // minimum gap between OTP mails per address
const FLOOR_MS = 600; // constant-time floor so known/unknown paths look alike

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const ddb = DynamoDBDocumentClient.from(
  new DynamoDBClient({ region: process.env.ENCLAVE_REGION }),
);
const ses = new SESClient({ region: process.env.ENCLAVE_REGION });

const hashCode = (email: string, code: string) =>
  createHash("sha256").update(`${email}:${code}`).digest("hex");

export async function handler(event: APIGatewayProxyEventV2) {
  const started = Date.now();
  const genericAfterFloor = async () => {
    // Equalize latency so the known vs unknown path can't be timed apart.
    await sleep(Math.max(0, FLOOR_MS - (Date.now() - started)));
    return ok({ message: "If that address is registered, a login code has been sent." });
  };

  const { email } = parseBody<{ email?: string }>(event);
  if (!email) return badRequest("email is required");
  const normalized = normalizeEmail(email);

  // Always return 200 so we don't leak which emails exist; only send mail to
  // known users (admins or anyone holding a project/team membership).
  if (await isKnownUser(normalized)) {
    const code = String(randomInt(0, 10 ** OTP_DIGITS)).padStart(OTP_DIGITS, "0");
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + TTL_SECONDS;

    try {
      await ddb.send(
        new PutCommand({
          TableName: process.env.OTP_TABLE,
          Item: {
            email: normalized,
            codeHash: hashCode(normalized, code),
            expiresAt,
            attempts: 0,
            lastSentAt: now,
          },
          // Resend throttle: refuse to overwrite a code mailed < RESEND_SECONDS ago.
          ConditionExpression: "attribute_not_exists(email) OR lastSentAt < :cutoff",
          ExpressionAttributeValues: { ":cutoff": now - RESEND_SECONDS },
        }),
      );
    } catch {
      // Throttled resend, or (any) write error — return the same generic 200.
      // A failure here must never distinguish this address from an unknown one.
      return genericAfterFloor();
    }

    try {
      await ses.send(
        new SendEmailCommand({
          Source: process.env.SES_SENDER,
          Destination: { ToAddresses: [normalized] },
          Message: {
            Subject: { Data: "Your enclave-envoy login code" },
            Body: {
              Text: {
                Data: `Your one-time login code is ${code}\n\nIt expires in ${TTL_SECONDS / 60} minutes. If you did not request this, ignore this email.`,
              },
            },
          },
        }),
      );
    } catch (err) {
      // Never surface SES errors to the caller — that would turn a known
      // address into a 5xx oracle. Log them, though: a misconfigured sender or
      // IAM scope would otherwise break login completely and silently.
      console.error("SES send failed", { name: (err as Error)?.name, message: (err as Error)?.message });
    }
  }

  return genericAfterFloor();
}
