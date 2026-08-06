/// <reference path="./.sst/platform/config.d.ts" />

/**
 * enclave-envoy infrastructure (SST v3 / ion).
 *
 * Provisions:
 *   - KMS master key (envelope-encryption root; never leaves KMS)
 *   - S3 bucket (project-id/stage-name/file) with a per-stage bucket policy
 *   - DynamoDB table for one-time login codes (TTL-expired)
 *   - One IAM role per stage; the bucket policy scopes each role to its stage's
 *     `<project>/<stage>/<file>` keys
 *   - HTTP API + Lambda functions: auth/request, auth/verify, access/whoami,
 *     crypto/datakey, s3/presign
 *
 * The CLI never gets AWS credentials. Every privileged action is brokered by a
 * Lambda that re-validates the caller's JWT and the users.yaml map on each call.
 */

// The complete set of valid stages. Each stage gets its own IAM role +
// bucket-policy statement; the AccessTable only grants stages from this list.
const stages = ["dev", "staging", "prod", "personal"];

// Bootstrap admins: these emails can always log in (and create the first
// projects). Everyone else must be invited to a project or team first.
const adminEmails = ["info@sp33c.tech"];

// The verified SES identity OTP mail is sent from. Used to scope the
// ses:SendEmail grant to exactly this identity (not every identity in the
// account). A domain identity covers any address at that domain.
const sesIdentity = "sp33c.tech";

// Edition: "opensource" is the core (projects, encrypted upload/view, CLI);
// "enterprise" adds team management. Editions are presets over the feature
// toggles below — individual flags can still be overridden after the spread.
const edition: "opensource" | "enterprise" = "enterprise";

const editionFeatures = {
  opensource: { landing: true, teams: false, fileDelete: true },
  enterprise: { landing: true, teams: true, fileDelete: true },
} as const;

// Feature toggles. Enforced in the Lambdas (functions/lib/features.ts) and
// baked into the web build — flip here, `sst deploy` to apply.
const features: Record<string, boolean> = {
  ...editionFeatures[edition],
  // per-flag overrides go here, e.g. `fileDelete: false`
};

export default $config({
  app(input) {
    return {
      name: "enclave-envoy",
      // Keep encrypted data and the KMS key around if you tear down prod by mistake.
      removal: input?.stage === "prod" ? "retain" : "remove",
      protect: input?.stage === "prod",
      home: "aws",
    };
  },

  async run() {
    const identity = await aws.getCallerIdentity({});
    const region = await aws.getRegion({});
    const accountId = identity.accountId;

    // Address that one-time-code emails are sent FROM. Must be a verified SES
    // identity in this account/region. Set via: `npx sst secret set SesSender ...`
    // or hard-code for the template:
    const sesSender = new sst.Secret("SesSender", "no-reply@example.com");

    // HMAC key used to sign/verify session JWTs.
    // `npx sst secret set JwtSigningKey "$(openssl rand -hex 32)"`
    const jwtKey = new sst.Secret("JwtSigningKey");

    // Confused-deputy guard: the presign Lambda must present this ExternalId to
    // assume a stage role, so an unrelated in-account principal that merely
    // holds sts:AssumeRole cannot. `npx sst secret set StageAssumeExternalId ...`
    const assumeExternalId = new sst.Secret("StageAssumeExternalId");

    // ---- KMS master key ---------------------------------------------------
    const key = new aws.kms.Key("EnclaveMasterKey", {
      description: "enclave-envoy envelope-encryption master key",
      enableKeyRotation: true,
      deletionWindowInDays: 14,
    });
    new aws.kms.Alias("EnclaveMasterKeyAlias", {
      name: `alias/enclave-envoy-${$app.stage}`,
      targetKeyId: key.keyId,
    });

    // ---- DynamoDB: one-time login codes -----------------------------------
    const otpTable = new sst.aws.Dynamo("OtpTable", {
      fields: { email: "string" },
      primaryIndex: { hashKey: "email" },
      ttl: "expiresAt", // epoch seconds; DynamoDB auto-deletes expired codes
    });

    // ---- DynamoDB: dynamic access map (projects, teams, memberships) ------
    // Replaces the old static users.yaml. Holds only access metadata — file
    // contents stay client-side-encrypted in S3.
    const accessTable = new sst.aws.Dynamo("AccessTable", {
      fields: { pk: "string", sk: "string", gsi1pk: "string", gsi1sk: "string" },
      primaryIndex: { hashKey: "pk", rangeKey: "sk" },
      globalIndexes: { gsi1: { hashKey: "gsi1pk", rangeKey: "gsi1sk" } },
    });

    // ---- Per-stage IAM roles ---------------------------------------------
    // Trusted by the account root; the presign Lambda is additionally granted
    // sts:AssumeRole on exactly these ARNs (see below). This avoids a circular
    // dependency between the roles and the function roles.
    const stageRoles = stages.map((stage) => {
      const role = new aws.iam.Role(`StageRole-${stage}`, {
        name: `enclave-envoy-${$app.stage}-${stage}`,
        // Root-principal trust avoids a create-order cycle with the presign
        // function role, but is gated on a secret ExternalId so that only the
        // presign Lambda (which knows it) can actually assume the role — a bare
        // in-account sts:AssumeRole is no longer sufficient.
        assumeRolePolicy: $jsonStringify({
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Principal: { AWS: `arn:aws:iam::${accountId}:root` },
              Action: "sts:AssumeRole",
              Condition: { StringEquals: { "sts:ExternalId": assumeExternalId.value } },
            },
          ],
        }),
        maxSessionDuration: 3600,
      });
      return { stage, role };
    });

    // ---- S3 bucket --------------------------------------------------------
    // S3 allows exactly one bucket policy, and enforceHttps makes SST manage
    // it — so the per-stage statements are merged into that same policy via
    // transform.policy instead of a standalone aws.s3.BucketPolicy resource.
    const bucket = new sst.aws.Bucket("VaultBucket", {
      enforceHttps: true, // adds a deny-non-TLS statement
      // Browser clients hit presigned URLs directly; without CORS every
      // cross-origin PUT/GET/DELETE fails preflight (the CLI is unaffected).
      cors: {
        allowMethods: ["GET", "PUT", "DELETE"],
        allowOrigins: ["*"],
        allowHeaders: ["*"],
      },
      transform: {
        policy: (args) => {
          args.policy = sst.aws.iamEdit(args.policy, (policy) => {
            for (const { stage, role } of stageRoles) {
              // Object-level access, scoped to this stage's prefix.
              policy.Statement.push({
                Sid: `Stage_${stage}_objects`,
                Effect: "Allow",
                Principal: { AWS: role.arn },
                Action: ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                Resource: $interpolate`arn:aws:s3:::${args.bucket}/*/${stage}/*`,
              });
              // Listing: stage roles may List the bucket, but only under their
              // own stage prefix (objects stay encrypted regardless).
              policy.Statement.push({
                Sid: `Stage_${stage}_list`,
                Effect: "Allow",
                Principal: { AWS: role.arn },
                Action: ["s3:ListBucket"],
                Resource: $interpolate`arn:aws:s3:::${args.bucket}`,
                Condition: { StringLike: { "s3:prefix": [`*/${stage}/*`, `*/${stage}`] } },
              });
            }
          });
        },
      },
    });

    const stageRoleArns = $jsonStringify(
      Object.fromEntries(stageRoles.map(({ stage, role }) => [stage, role.arn])),
    );

    // ---- HTTP API + functions --------------------------------------------
    // Stage-wide throttle caps brute-force / abuse volume (the force multiplier
    // for OTP guessing, SES bombing and KMS/Dynamo cost abuse). A WAFv2
    // rate-based rule keyed on IP is a recommended additional layer.
    const api = new sst.aws.ApiGatewayV2("Api", {
      cors: {
        allowOrigins: ["*"],
        allowMethods: ["GET", "POST"],
        allowHeaders: ["authorization", "content-type"],
      },
      transform: {
        stage: {
          defaultRouteSettings: {
            throttlingRateLimit: 20, // steady-state requests/sec across the API
            throttlingBurstLimit: 40,
          },
        },
      },
    });

    // Shared environment for JWT-verifying endpoints.
    const baseEnv = {
      ENCLAVE_REGION: region.name,
      JWT_SIGNING_KEY: jwtKey.value,
      STAGES: JSON.stringify(stages),
      ACCESS_TABLE: accessTable.name,
      FEATURES: JSON.stringify(features),
      EDITION: edition,
    };

    // Read-only access-map lookups (canAccess / permissionsFor / isKnownUser).
    const accessRead = {
      actions: ["dynamodb:GetItem", "dynamodb:Query"],
      resources: [accessTable.arn, $interpolate`${accessTable.arn}/index/*`],
    };

    api.route("POST /auth/request", {
      handler: "functions/auth/request.handler",
      environment: {
        ...baseEnv,
        OTP_TABLE: otpTable.name,
        SES_SENDER: sesSender.value,
        ADMIN_EMAILS: adminEmails.join(","),
      },
      permissions: [
        accessRead,
        { actions: ["dynamodb:PutItem"], resources: [otpTable.arn] },
        {
          actions: ["ses:SendEmail"],
          resources: [
            $interpolate`arn:aws:ses:${region.name}:${accountId}:identity/${sesIdentity}`,
          ],
        },
      ],
    });

    api.route("POST /auth/verify", {
      handler: "functions/auth/verify.handler",
      environment: { ...baseEnv, OTP_TABLE: otpTable.name },
      permissions: [
        accessRead,
        {
          actions: ["dynamodb:GetItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"],
          resources: [otpTable.arn],
        },
      ],
    });

    api.route("GET /access/whoami", {
      handler: "functions/access/whoami.handler",
      environment: baseEnv,
      permissions: [accessRead],
    });

    api.route("POST /crypto/datakey", {
      handler: "functions/crypto/datakey.handler",
      environment: { ...baseEnv, KMS_KEY_ID: key.keyId },
      permissions: [
        accessRead,
        { actions: ["kms:GenerateDataKey", "kms:Decrypt"], resources: [key.arn] },
      ],
    });

    api.route("POST /s3/presign", {
      handler: "functions/s3/presign.handler",
      environment: {
        ...baseEnv,
        BUCKET: bucket.name,
        STAGE_ROLE_ARNS: stageRoleArns,
        STAGE_ASSUME_EXTERNAL_ID: assumeExternalId.value,
      },
      permissions: [
        accessRead,
        {
          actions: ["sts:AssumeRole"],
          resources: stageRoles.map((s) => s.role.arn),
        },
      ],
    });

    // Project/team administration (create, members, grants).
    const adminDef = {
      handler: "functions/admin/handler.handler",
      environment: baseEnv,
      permissions: [
        {
          actions: [
            "dynamodb:GetItem",
            "dynamodb:Query",
            "dynamodb:PutItem",
            "dynamodb:DeleteItem",
            "dynamodb:UpdateItem",
            "dynamodb:TransactWriteItems",
          ],
          resources: [accessTable.arn, $interpolate`${accessTable.arn}/index/*`],
        },
      ],
    };
    api.route("GET /admin/{proxy+}", adminDef);
    api.route("POST /admin/{proxy+}", adminDef);

    // ---- Web frontend (static SPA; VITE_API_URL baked at build time) ------
    const site = new sst.aws.StaticSite("Web", {
      path: "../web",
      build: { command: "npm run build", output: "dist" },
      environment: {
        VITE_API_URL: api.url,
        VITE_FEATURES: JSON.stringify(features),
        VITE_EDITION: edition,
      },
    });

    return {
      ApiUrl: api.url,
      SiteUrl: site.url,
      Bucket: bucket.name,
      KmsKeyId: key.keyId,
    };
  },
});
