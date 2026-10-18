import { randomBytes } from "node:crypto";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, TransactWriteCommand } from "@aws-sdk/lib-dynamodb";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import type { Claims } from "./jwt.js";

/**
 * Audit trail for the CIEM view (enterprise `ciem` feature). AUDIT_TABLE:
 *
 *   PROJECT#<p> / <iso-ts>#<rand>        one event: who, kind, stage, action, file, ip
 *                                        gsi1: PRINCIPAL#<sub> -> <iso-ts>   ttl: expiresAt
 *   USAGE#<p>   / <principal>#<stage>    rollup: lastRead/lastWrite + counts (no ttl)
 *
 * The rollup is what the entitlement findings read ("granted prod, never used
 * it"); the events are the forensic log. Both are written in one transaction.
 *
 * Fail-closed: vault endpoints await record() before handing out a data key or
 * a presigned URL, so an access that could not be recorded does not happen.
 * Without AUDIT_TABLE (feature off) this is a no-op.
 *
 * Runner tokens act for the human who launched the run; their usage is rolled
 * up under that human (`actor`), while the event keeps the runner principal.
 */

export type AuditAction =
  | "decrypt"
  | "generate"
  | "download"
  | "upload"
  | "delete"
  | "list"
  | "workload.login"
  | "run.launch"
  | "run.stop";

const WRITES: AuditAction[] = ["generate", "upload", "delete"];
const RETENTION_DAYS = () => Number(process.env.AUDIT_RETENTION_DAYS ?? "90");

const ddb = DynamoDBDocumentClient.from(
  new DynamoDBClient({ region: process.env.ENCLAVE_REGION }),
);

export function principalKind(claims: Pick<Claims, "typ" | "sub">): "human" | "machine" | "runner" {
  if (claims.typ !== "machine") return "human";
  return claims.sub.startsWith("runner:") ? "runner" : "machine";
}

export interface AuditEntry {
  claims: Claims;
  project: string;
  stage: string;
  action: AuditAction;
  file?: string;
  /** Who the usage counts for, when not the principal itself (runner -> launcher). */
  actor?: string;
  detail?: Record<string, string>;
}

export async function record(event: APIGatewayProxyEventV2 | null, entry: AuditEntry): Promise<void> {
  const table = process.env.AUDIT_TABLE;
  if (!table) return;

  const now = new Date();
  const ts = now.toISOString();
  const principal = entry.claims.sub;
  const actor = entry.actor ?? principal;
  const write = WRITES.includes(entry.action);
  const countsAsUse = entry.action !== "workload.login" && entry.action !== "run.stop";
  const ip = event?.requestContext?.http?.sourceIp;
  const ua = event?.requestContext?.http?.userAgent?.slice(0, 200);

  const item: Record<string, unknown> = {
    pk: `PROJECT#${entry.project}`,
    sk: `${ts}#${randomBytes(4).toString("hex")}`,
    gsi1pk: `PRINCIPAL#${principal}`,
    gsi1sk: ts,
    principal,
    kind: principalKind(entry.claims),
    stage: entry.stage,
    action: entry.action,
    expiresAt: Math.floor(now.getTime() / 1000) + RETENTION_DAYS() * 86400,
  };
  if (entry.file) item.file = entry.file;
  if (actor !== principal) item.actor = actor;
  if (entry.claims.src) item.src = entry.claims.src;
  if (ip) item.ip = ip;
  if (ua) item.ua = ua;
  if (entry.detail) item.detail = entry.detail;

  const items: NonNullable<ConstructorParameters<typeof TransactWriteCommand>[0]["TransactItems"]> = [
    { Put: { TableName: table, Item: item } },
  ];
  if (countsAsUse) {
    const field = write ? "Write" : "Read";
    items.push({
      Update: {
        TableName: table,
        Key: { pk: `USAGE#${entry.project}`, sk: `${actor}#${entry.stage}` },
        UpdateExpression: `SET last${field} = :ts, principal = :p, stage = :s ADD ${field.toLowerCase()}s :one`,
        ExpressionAttributeValues: { ":ts": ts, ":p": actor, ":s": entry.stage, ":one": 1 },
      },
    });
  }
  await ddb.send(new TransactWriteCommand({ TransactItems: items }));
}
