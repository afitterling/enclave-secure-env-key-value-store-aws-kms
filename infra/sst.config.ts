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

// Custom domain per deployment stage. A stage with no entry runs on the
// CloudFront default domain.
//
// PREREQUISITE, and the deploy fails without it: SST has to be able to write
// the ACM validation records. A Route 53 hosted zone in this account is handled
// automatically; a domain hosted anywhere else needs `dns: false` plus a cert
// you validated by hand.
//
// enclavecore.app is registered at Vercel but delegated to Route 53 zone
// Z05132714ZL2SHERUCOL via Vercel's custom-nameserver setting (2026-09-20).
// Apex only — www is not registered here and will not resolve.
const siteDomains: Record<string, string> = {
  production: "enclavecore.app",
};

// Browser origins allowed to reach the presigned S3 URLs. The API is same-origin
// now (served at /api on the site distribution), so this really only governs the
// bucket, where the browser PUTs and GETs directly.
//
// Deliberately NOT derived from `siteDomains`: during a domain cutover the site
// answers on both the CloudFront default domain and the custom one, and an
// origin list naming only the new domain breaks uploads on the live site. List
// every origin the app is actually served from.
const webOrigins: Record<string, string[]> = {
  production: [
    "https://d2lessbpccmuy9.cloudfront.net", // current production distribution
    "https://enclavecore.app", // harmless before cutover, required after
  ],
};

function allowedOrigins(stage: string): string[] {
  const configured = webOrigins[stage];
  if (configured?.length) return configured;
  if (stage === "production") {
    throw new Error(
      "Refusing to deploy production with wildcard CORS on the vault bucket. " +
        "Add every origin the site is served from to `webOrigins.production` " +
        "in infra/sst.config.ts.",
    );
  }
  return ["*"];
}

// This is the open-source edition. Team management (teams, team grants)
// ships in the enterprise edition, maintained in a separate repository.
const edition = "opensource";

// Feature toggles. Enforced in the Lambdas (functions/lib/features.ts) and
// baked into the web build — flip here, `sst deploy` to apply.
const features: Record<string, boolean> = {
  landing: true, // public landing page at "/" (off => straight to login)
  fileDelete: true, // presign delete op + delete buttons in the UI
};

export default $config({
  app(input) {
    return {
      name: "enclave-envoy",
      // Keep encrypted data and the KMS key around if you tear down production
      // by mistake. NB: this is the *deployment* stage name ("production"), not
      // the vault stage "prod" in `stages` above — renaming one does not rename
      // the other, and getting it wrong silently disables both guards.
      removal: input?.stage === "production" ? "retain" : "remove",
      protect: input?.stage === "production",
      home: "aws",
    };
  },

  async run() {
    const identity = await aws.getCallerIdentity({});
    const region = await aws.getRegion({});
    const accountId = identity.accountId;
    const origins = allowedOrigins($app.stage);
    const siteDomain = siteDomains[$app.stage];
    const isProduction = $app.stage === "production";

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

    // Shared secret CloudFront injects as a request header on the /api origin.
    // The Lambdas reject requests that lack it, so the raw execute-api URL
    // cannot be used to bypass the edge WAF. Unset means "not enforced", which
    // keeps existing stages working until the token is set on them:
    // `npx sst secret set EdgeOriginToken "$(openssl rand -hex 32)" --stage <s>`
    const edgeToken = new sst.Secret("EdgeOriginToken", "");

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
        allowOrigins: origins,
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
        allowOrigins: origins,
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
      EDGE_ORIGIN_TOKEN: edgeToken.value,
    };

    // Read-only access-map lookups (canAccess / permissionsFor / isKnownUser).
    const accessRead = {
      actions: ["dynamodb:GetItem", "dynamodb:Query"],
      resources: [accessTable.arn, $interpolate`${accessTable.arn}/index/*`],
    };

    api.route("POST /api/auth/request", {
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
          // Scoped to our own identity (so a compromise can't spoof other
          // verified domains). SendEmail is also authorized against the
          // identity's default configuration set, which must be allowed too —
          // omitting it fails closed with AccessDenied.
          actions: ["ses:SendEmail"],
          resources: [
            $interpolate`arn:aws:ses:${region.name}:${accountId}:identity/${sesIdentity}`,
            $interpolate`arn:aws:ses:${region.name}:${accountId}:configuration-set/*`,
          ],
        },
      ],
    });

    api.route("POST /api/auth/verify", {
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

    api.route("GET /api/access/whoami", {
      handler: "functions/access/whoami.handler",
      environment: baseEnv,
      permissions: [accessRead],
    });

    api.route("POST /api/crypto/datakey", {
      handler: "functions/crypto/datakey.handler",
      environment: { ...baseEnv, KMS_KEY_ID: key.keyId },
      permissions: [
        accessRead,
        { actions: ["kms:GenerateDataKey", "kms:Decrypt"], resources: [key.arn] },
      ],
    });

    api.route("POST /api/s3/presign", {
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
    api.route("GET /api/admin/{proxy+}", adminDef);
    api.route("POST /api/admin/{proxy+}", adminDef);

    // ---- Edge WAF ---------------------------------------------------------
    // The Web ACL itself is owned by the central `waf-acls` app (AWS-Admin/WAF
    // (sst), SEC-006) as `EnclaveEdge`: the same per-IP flood backstop (2000 /
    // 5 min) and the same tighter cap on POST under /api/ (100 / 5 min) this
    // stack used to define for itself, plus AWS's managed rule groups, request
    // logging and attack alarms. That app publishes the ARN to SSM; we read it
    // and bind it to the distribution below. The param lives in us-east-1
    // whatever the origin region, hence the lookup-only provider. Production
    // only: a Web ACL bills per month plus per request.
    const edgeAclArn = isProduction
      ? aws.ssm.getParameterOutput(
          { name: "/waf/production/EnclaveEdge" },
          { provider: new aws.Provider("UsEast1", { region: "us-east-1" }) },
        ).value
      : undefined;

    // ---- Web frontend -----------------------------------------------------
    // The API is served from this same distribution under /api, which is what
    // makes the WAF above meaningful: AWS WAF cannot attach to an API Gateway
    // HTTP API directly, only to CloudFront. Being same-origin also means the
    // browser never makes a cross-origin API call, so API CORS stops mattering.
    //
    // VITE_API_URL is the relative "/api" rather than the API's own URL, which
    // also breaks what would otherwise be a cycle (site needs the API URL, the
    // distribution needs the API as an origin).
    const apiHost = api.url.apply((u) => new URL(u).host);

    const site = new sst.aws.StaticSite("Web", {
      path: "../web",
      build: { command: "npm run build", output: "dist" },
      ...(siteDomain ? { domain: siteDomain } : {}),
      environment: {
        VITE_API_URL: "/api",
        VITE_FEATURES: JSON.stringify(features),
        VITE_EDITION: edition,
      },
      transform: {
        cdn: (args) => {
          args.origins = $output({
            origins: args.origins,
            host: apiHost,
            token: edgeToken.value,
          }).apply(({ origins, host, token }) => [
            ...origins,
            {
              originId: "api",
              domainName: host,
              // Proves the request came through CloudFront. The Lambdas reject
              // anything without it, so the execute-api URL cannot be used to
              // walk around the Web ACL.
              //
              // The name must not start with `x-edge-` or `x-amz-cf-`:
              // CloudFront reserves both prefixes and rejects the distribution
              // update with "The parameter HeaderName ... is not allowed".
              //
              // Omitted entirely when no token is set, which is how a stage
              // runs with the check disabled.
              ...(token ? { customHeaders: [{ name: "x-enclave-origin", value: token }] } : {}),
              customOriginConfig: {
                originProtocolPolicy: "https-only",
                httpPort: 80,
                httpsPort: 443,
                originSslProtocols: ["TLSv1.2"],
              },
            },
          ]);

          args.orderedCacheBehaviors = $output(args.orderedCacheBehaviors ?? []).apply(
            (behaviors) => [
              ...behaviors,
              {
                pathPattern: "/api/*",
                targetOriginId: "api",
                viewerProtocolPolicy: "redirect-to-https",
                allowedMethods: ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"],
                cachedMethods: ["GET", "HEAD"],
                compress: true,
                // Managed "CachingDisabled" — an API response must never be
                // served from the edge cache to another user.
                cachePolicyId: "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
                // Managed "AllViewerExceptHostHeader" — forwards Authorization
                // and the body, but keeps the viewer Host off the origin, which
                // API Gateway rejects.
                originRequestPolicyId: "b689b0a8-53d0-40ab-baf2-68738e2966ac",
              },
            ],
          );

          if (edgeAclArn) {
            args.transform = {
              ...args.transform,
              distribution: (dist) => {
                dist.webAclId = edgeAclArn;
              },
            };
          }
        },
      },
    });

    return {
      // What the CLI should be configured with. Goes through CloudFront, so it
      // is covered by the Web ACL; the raw api.url below bypasses it and is
      // rejected once EdgeOriginToken is set.
      ApiUrl: $interpolate`${site.url}/api`,
      ApiOriginUrl: api.url,
      SiteUrl: site.url,
      Bucket: bucket.name,
      KmsKeyId: key.keyId,
    };
  },
});
