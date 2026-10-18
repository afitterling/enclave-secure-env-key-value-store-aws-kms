import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import { claimsMatch, parseCallerArn, validateBinding, GITHUB_ISSUER } from "../functions/lib/machines.js";
import { verifyOidcToken, _resetJwksCache } from "../functions/lib/oidc.js";
import { verifySignedStsRequest } from "../functions/lib/awsiam.js";
import { issue, issueMachine, requireAuth, requirePrincipal } from "../functions/lib/jwt.js";
import { authorize } from "../functions/lib/access.js";

process.env.STAGES = JSON.stringify(["dev", "staging", "prod", "personal"]);
process.env.FEATURES = JSON.stringify({ machineIdentities: true });
process.env.ACCESS_TABLE = "access";

const SECRET = "test-secret";
const bearer = (t: string) => ({ headers: { authorization: `Bearer ${t}` } });

// ---- binding validation -----------------------------------------------------

describe("validateBinding", () => {
  const gh = (claims: Record<string, string>) =>
    validateBinding({ id: "ci", kind: "oidc", issuer: GITHUB_ISSUER, claims, stages: ["prod"] });

  it("accepts a GitHub binding pinned to an owner", () => {
    expect(gh({ sub: "repo:acme/api:ref:refs/heads/main" }).ok).toBe(true);
    expect(gh({ repository: "acme/api", ref: "refs/heads/*" }).ok).toBe(true);
    expect(gh({ repository_id: "123456" }).ok).toBe(true);
  });

  it("refuses GitHub bindings that admit every repository on github.com", () => {
    expect(gh({ ref: "refs/heads/main" }).ok).toBe(false);
    expect(gh({ sub: "repo:*/api:ref:refs/heads/main" }).ok).toBe(false);
    expect(gh({ repository: "*/api" }).ok).toBe(false);
    expect(gh({ sub: "*" }).ok).toBe(false);
  });

  it("refuses server-checked claims, unsafe issuers and match-anything patterns", () => {
    expect(gh({ sub: "repo:acme/api:*", aud: "x" }).ok).toBe(false);
    for (const issuer of ["http://gitlab.com", "https://10.0.0.1", "https://localhost", "https://metadata.internal"]) {
      expect(
        validateBinding({ id: "x", kind: "oidc", issuer, claims: { sub: "project_path:a/b:*" }, stages: ["dev"] }).ok,
      ).toBe(false);
    }
    expect(
      validateBinding({ id: "x", kind: "oidc", issuer: "https://gitlab.com", claims: { sub: "**" }, stages: ["dev"] }).ok,
    ).toBe(false);
  });

  it("validates AWS bindings strictly", () => {
    const aws = (account: string, role: string) =>
      validateBinding({ id: "task", kind: "aws", account, role, stages: ["dev"], access: "read" });
    expect(aws("123456789012", "api-task-role").ok).toBe(true);
    expect(aws("1234", "api-task-role").ok).toBe(false);
    expect(aws("123456789012", "api-*").ok).toBe(false);
    expect(aws("123456789012", "path/role").ok).toBe(false);
  });

  it("rejects unknown stages and access levels", () => {
    expect(validateBinding({ id: "x", kind: "aws", account: "123456789012", role: "r", stages: ["qa"] }).ok).toBe(false);
    expect(
      validateBinding({ id: "x", kind: "aws", account: "123456789012", role: "r", stages: ["dev"], access: "admin" }).ok,
    ).toBe(false);
  });
});

describe("claimsMatch", () => {
  it("treats * as 'anything but a colon'", () => {
    const c = { sub: "repo:acme/api:ref:refs/heads/*" };
    expect(claimsMatch(c, { sub: "repo:acme/api:ref:refs/heads/main" })).toBe(true);
    expect(claimsMatch(c, { sub: "repo:acme/api:ref:refs/heads/feat/x" })).toBe(true);
    expect(claimsMatch(c, { sub: "repo:acme/api:environment:prod" })).toBe(false);
    expect(claimsMatch({ sub: "repo:acme/*:ref:refs/heads/main" }, { sub: "repo:acme/x:y:ref:refs/heads/main" })).toBe(false);
  });

  it("needs every constraint, compares numbers as strings, never matches empty", () => {
    expect(claimsMatch({ repository: "acme/api", repository_id: "42" }, { repository: "acme/api", repository_id: 42 })).toBe(true);
    expect(claimsMatch({ repository: "acme/api", ref: "refs/heads/main" }, { repository: "acme/api" })).toBe(false);
    expect(claimsMatch({}, { sub: "x" })).toBe(false);
    expect(claimsMatch({ sub: "a.c" }, { sub: "abc" })).toBe(false); // regex metachar escaped
  });
});

describe("parseCallerArn", () => {
  it("extracts account and role from assumed-role and role ARNs", () => {
    expect(parseCallerArn("arn:aws:sts::123456789012:assumed-role/task-role/5f2c9")).toEqual({
      account: "123456789012",
      role: "task-role",
      session: "5f2c9",
    });
    expect(parseCallerArn("arn:aws:iam::123456789012:role/svc/path/my-role")).toEqual({
      account: "123456789012",
      role: "my-role",
    });
    expect(parseCallerArn("arn:aws:iam::123456789012:user/alice")).toBeNull();
  });
});

// ---- OIDC verification --------------------------------------------------------

const ISSUER = "https://issuer.example.com";
const AUD = "enclave-envoy:123456789012:dev";

function makeKey(kind: "rsa" | "ec") {
  const pair =
    kind === "rsa"
      ? generateKeyPairSync("rsa", { modulusLength: 2048 })
      : generateKeyPairSync("ec", { namedCurve: "P-256" });
  return pair;
}

function signJwt(privateKey: KeyObject, alg: "RS256" | "ES256", kid: string, claims: Record<string, unknown>) {
  const h = Buffer.from(JSON.stringify({ alg, kid, typ: "JWT" })).toString("base64url");
  const p = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const sig = cryptoSign(
    "sha256",
    Buffer.from(`${h}.${p}`),
    alg === "ES256" ? { key: privateKey, dsaEncoding: "ieee-p1363" } : privateKey,
  ).toString("base64url");
  return `${h}.${p}.${sig}`;
}

describe("verifyOidcToken", () => {
  const rsa = makeKey("rsa");
  const ec = makeKey("ec");
  let jwks: object[];
  const now = () => Math.floor(Date.now() / 1000);
  const good = () => ({ iss: ISSUER, aud: AUD, sub: "repo:acme/api:ref:refs/heads/main", exp: now() + 300, iat: now() });

  beforeEach(() => {
    _resetJwksCache();
    jwks = [
      { ...rsa.publicKey.export({ format: "jwk" }), kid: "r1", alg: "RS256", use: "sig" },
      { ...ec.publicKey.export({ format: "jwk" }), kid: "e1" },
    ];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url === `${ISSUER}/.well-known/openid-configuration`) {
          return new Response(JSON.stringify({ issuer: ISSUER, jwks_uri: `${ISSUER}/keys` }));
        }
        if (url === `${ISSUER}/keys`) return new Response(JSON.stringify({ keys: jwks }));
        return new Response("nope", { status: 404 });
      }),
    );
  });
  afterEach(() => vi.unstubAllGlobals());

  it("accepts RS256 and ES256 tokens from the issuer", async () => {
    await expect(verifyOidcToken(signJwt(rsa.privateKey, "RS256", "r1", good()), ISSUER, AUD)).resolves.toMatchObject({
      sub: "repo:acme/api:ref:refs/heads/main",
    });
    await expect(verifyOidcToken(signJwt(ec.privateKey, "ES256", "e1", good()), ISSUER, AUD)).resolves.toBeTruthy();
  });

  it("accepts an audience list that contains ours", async () => {
    const t = signJwt(rsa.privateKey, "RS256", "r1", { ...good(), aud: ["other", AUD] });
    await expect(verifyOidcToken(t, ISSUER, AUD)).resolves.toBeTruthy();
  });

  it("rejects wrong audience, wrong issuer, expiry, future nbf", async () => {
    for (const claims of [
      { ...good(), aud: "someone-else" },
      { ...good(), iss: "https://evil.example.com" },
      { ...good(), exp: now() - 120 },
      { ...good(), nbf: now() + 600 },
    ]) {
      await expect(verifyOidcToken(signJwt(rsa.privateKey, "RS256", "r1", claims), ISSUER, AUD)).rejects.toThrow();
    }
  });

  it("rejects a token signed by a key the issuer does not publish", async () => {
    const other = makeKey("rsa");
    await expect(verifyOidcToken(signJwt(other.privateKey, "RS256", "r1", good()), ISSUER, AUD)).rejects.toThrow(
      /bad signature/,
    );
  });

  it("rejects alg=none and HS256 (key-confusion)", async () => {
    const p = Buffer.from(JSON.stringify(good())).toString("base64url");
    for (const alg of ["none", "HS256"]) {
      const h = Buffer.from(JSON.stringify({ alg, kid: "r1" })).toString("base64url");
      await expect(verifyOidcToken(`${h}.${p}.`, ISSUER, AUD)).rejects.toThrow(/unsupported alg/);
    }
  });

  it("refetches the JWKS once for an unknown kid (key rotation)", async () => {
    const rotated = makeKey("rsa");
    await verifyOidcToken(signJwt(rsa.privateKey, "RS256", "r1", good()), ISSUER, AUD); // warm cache
    jwks.push({ ...rotated.publicKey.export({ format: "jwk" }), kid: "r2" });
    // Inside MIN_REFETCH of the first fetch, so the new key is not seen yet...
    await expect(verifyOidcToken(signJwt(rotated.privateKey, "RS256", "r2", good()), ISSUER, AUD)).rejects.toThrow(
      /no matching signing key/,
    );
    // ...and is once that window has passed.
    vi.useFakeTimers({ now: Date.now() + 61_000 });
    try {
      await expect(verifyOidcToken(signJwt(rotated.privateKey, "RS256", "r2", good()), ISSUER, AUD)).resolves.toBeTruthy();
    } finally {
      vi.useRealTimers();
    }
  });

  it("refuses a discovery document that names another issuer", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ issuer: "https://other.example.com", jwks_uri: `${ISSUER}/keys` }))),
    );
    await expect(verifyOidcToken(signJwt(rsa.privateKey, "RS256", "r1", good()), ISSUER, AUD)).rejects.toThrow(
      /different issuer/,
    );
  });
});

// ---- AWS signed STS -----------------------------------------------------------

describe("verifySignedStsRequest", () => {
  const body = Buffer.from("Action=GetCallerIdentity&Version=2011-06-15").toString("base64");
  const headers = {
    Authorization:
      "AWS4-HMAC-SHA256 Credential=AKIA/20261019/eu-central-1/sts/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-enclave-server-id, Signature=abc",
    "X-Amz-Date": "20261019T120000Z",
    "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
    "x-enclave-server-id": AUD,
    "X-Evil": "dropped",
  };
  const req = { method: "POST", url: "https://sts.eu-central-1.amazonaws.com/", headers, body };
  const xml = `<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:sts::123456789012:assumed-role/task-role/abc</Arn><UserId>AROA:abc</UserId><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`;
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn(async () => new Response(xml));
    vi.stubGlobal("fetch", fetchMock);
  });
  afterEach(() => vi.unstubAllGlobals());

  it("forwards an allowlisted, server-bound request and parses the caller", async () => {
    await expect(verifySignedStsRequest(req, AUD)).resolves.toEqual({
      arn: "arn:aws:sts::123456789012:assumed-role/task-role/abc",
      account: "123456789012",
      userId: "AROA:abc",
    });
    const [, init] = fetchMock.mock.calls[0];
    expect(Object.keys(init.headers)).not.toContain("x-evil");
    expect(init.redirect).toBe("error");
  });

  it("refuses non-STS URLs, other actions, other audiences and unsigned server ids", async () => {
    const cases = [
      { ...req, url: "https://evil.example.com/" },
      { ...req, url: "https://sts.amazonaws.com.evil.com/" },
      { ...req, url: "https://sts.amazonaws.com/?Action=AssumeRole" },
      { ...req, body: Buffer.from("Action=AssumeRole&Version=2011-06-15").toString("base64") },
      { ...req, headers: { ...headers, "x-enclave-server-id": "other-deployment" } },
      { ...req, headers: { ...headers, Authorization: headers.Authorization.replace(";x-enclave-server-id", "") } },
      { ...req, method: "GET" },
    ];
    for (const c of cases) await expect(verifySignedStsRequest(c, AUD)).rejects.toThrow();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("surfaces an STS rejection", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("<Error/>", { status: 403 })));
    await expect(verifySignedStsRequest(req, AUD)).rejects.toThrow(/STS rejected/);
  });
});

// ---- tokens and authorization ---------------------------------------------------

describe("machine tokens", () => {
  const machine = issueMachine({ prj: "webapp", mid: "ci", rev: "r1", src: "x" }, SECRET);

  it("are refused by requireAuth (human-only endpoints) and accepted by requirePrincipal", () => {
    expect(() => requireAuth(bearer(machine), SECRET)).toThrow(/machine tokens/);
    expect(requirePrincipal(bearer(machine), SECRET)).toMatchObject({ typ: "machine", prj: "webapp", mid: "ci" });
    expect(requireAuth(bearer(issue("a@b.co", SECRET)), SECRET).sub).toBe("a@b.co");
  });
});

describe("authorize (machine path)", () => {
  const claims = requirePrincipal(bearer(issueMachine({ prj: "webapp", mid: "ci", rev: "r1", src: "x" }, SECRET)), SECRET);
  let item: Record<string, unknown> | undefined;

  beforeEach(() => {
    item = { pk: "PROJECT#webapp", sk: "MACHINE#ci", rev: "r1", stages: ["dev", "prod"], access: "read" };
    vi.spyOn(DynamoDBDocumentClient.prototype, "send").mockImplementation(async () => ({ Item: item }) as never);
  });
  afterEach(() => vi.restoreAllMocks());

  it("allows reads on bound stages only", async () => {
    expect(await authorize(claims, "webapp", "prod", "read")).toBe(true);
    expect(await authorize(claims, "webapp", "staging", "read")).toBe(false);
    expect(await authorize(claims, "other", "prod", "read")).toBe(false);
  });

  it("needs write access to write", async () => {
    expect(await authorize(claims, "webapp", "prod", "write")).toBe(false);
    item!.access = "write";
    expect(await authorize(claims, "webapp", "prod", "write")).toBe(true);
  });

  it("stops working the moment the binding is edited or removed", async () => {
    item!.rev = "r2";
    expect(await authorize(claims, "webapp", "prod", "read")).toBe(false);
    item = undefined;
    expect(await authorize(claims, "webapp", "prod", "read")).toBe(false);
  });

  it("is off when the feature is off", async () => {
    const before = process.env.FEATURES;
    process.env.FEATURES = "{}";
    try {
      expect(await authorize(claims, "webapp", "prod", "read")).toBe(false);
    } finally {
      process.env.FEATURES = before;
    }
  });
});
