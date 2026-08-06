import { STSClient, AssumeRoleCommand } from "@aws-sdk/client-sts";
import { S3Client } from "@aws-sdk/client-s3";

const sts = new STSClient({ region: process.env.ENCLAVE_REGION });

/**
 * Assume the IAM role that the bucket policy scopes to `<project>/<stage>/<file>`
 * keys for this stage, and return an S3 client using those temporary credentials.
 * Any presigned URL produced by this client therefore inherits the stage-scoped
 * permission boundary — the bucket policy is what actually enforces "this stage,
 * this prefix, nothing else".
 */
export async function s3ForStage(stage: string, sessionName: string): Promise<S3Client> {
  const roleArns: Record<string, string> = JSON.parse(process.env.STAGE_ROLE_ARNS ?? "{}");
  const roleArn = roleArns[stage];
  if (!roleArn) throw new Error(`no role configured for stage '${stage}'`);

  const out = await sts.send(
    new AssumeRoleCommand({
      RoleArn: roleArn,
      RoleSessionName: sessionName.replace(/[^\w+=,.@-]/g, "_").slice(0, 64),
      DurationSeconds: 900,
      // Required by the stage-role trust policy (confused-deputy guard).
      ExternalId: process.env.STAGE_ASSUME_EXTERNAL_ID,
    }),
  );
  const c = out.Credentials!;
  return new S3Client({
    region: process.env.ENCLAVE_REGION,
    credentials: {
      accessKeyId: c.AccessKeyId!,
      secretAccessKey: c.SecretAccessKey!,
      sessionToken: c.SessionToken!,
    },
  });
}
