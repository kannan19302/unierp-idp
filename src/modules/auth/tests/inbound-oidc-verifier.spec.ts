import { beforeAll, describe, expect, it } from "vitest";
import {
  SignJWT,
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  type JWK,
  type KeyLike,
} from "jose";
import {
  InboundOidcClaimError,
  verifyInboundOidcToken,
} from "../inbound-oidc-verifier";

const issuer = "https://login.example.test/tenant-a";
const clientId = "client-a";
const nonce = "one-time-nonce";

let currentPrivateKey: KeyLike;
let previousPrivateKey: KeyLike;
let forgedPrivateKey: KeyLike;
let rotatingKeys: ReturnType<typeof createLocalJWKSet>;

async function signingPair(kid: string) {
  const pair = await generateKeyPair("RS256");
  const publicJwk = await exportJWK(pair.publicKey);
  return {
    privateKey: pair.privateKey,
    publicJwk: { ...publicJwk, kid, alg: "RS256", use: "sig" } as JWK,
  };
}

beforeAll(async () => {
  const current = await signingPair("current");
  const previous = await signingPair("previous");
  const forged = await signingPair("forged");
  currentPrivateKey = current.privateKey;
  previousPrivateKey = previous.privateKey;
  forgedPrivateKey = forged.privateKey;
  rotatingKeys = createLocalJWKSet({ keys: [current.publicJwk, previous.publicJwk] });
});

async function token(
  privateKey: KeyLike,
  options: {
    kid?: string;
    issuer?: string;
    audience?: string | string[];
    authorizedParty?: string;
    nonce?: string;
    expiresIn?: string;
    issuedAt?: number;
  } = {},
) {
  let jwt = new SignJWT({
    email: "person@example.test",
    email_verified: true,
    nonce: options.nonce ?? nonce,
    ...(options.authorizedParty ? { azp: options.authorizedParty } : {}),
  })
    .setProtectedHeader({ alg: "RS256", kid: options.kid ?? "current" })
    .setIssuer(options.issuer ?? issuer)
    .setAudience(options.audience ?? clientId)
    .setIssuedAt(options.issuedAt ?? Math.floor(Date.now() / 1000));
  jwt = jwt.setExpirationTime(options.expiresIn ?? "2m");
  return jwt.sign(privateKey);
}

const policy = {
  issuer,
  clientId,
  nonce,
  algorithms: ["RS256"],
  clockToleranceSeconds: 0,
};

describe("inbound OIDC token verifier", () => {
  it("accepts both current and previous advertised keys during rotation", async () => {
    const current = await token(currentPrivateKey, { kid: "current" });
    const previous = await token(previousPrivateKey, { kid: "previous" });

    await expect(verifyInboundOidcToken(current, rotatingKeys, policy)).resolves.toMatchObject({ nonce });
    await expect(verifyInboundOidcToken(previous, rotatingKeys, policy)).resolves.toMatchObject({ nonce });
  });

  it("rejects a token signed by an unadvertised key", async () => {
    const forged = await token(forgedPrivateKey, { kid: "forged" });
    await expect(verifyInboundOidcToken(forged, rotatingKeys, policy)).rejects.toThrow();
  });

  it.each([
    ["wrong issuer", { issuer: "https://attacker.example.test" }],
    ["wrong audience", { audience: "other-client" }],
    ["expired token", { expiresIn: "-1s" }],
    ["stale issued-at", { issuedAt: Math.floor(Date.now() / 1000) - 600 }],
  ])("rejects %s", async (_label, overrides) => {
    const signed = await token(currentPrivateKey, overrides);
    await expect(verifyInboundOidcToken(signed, rotatingKeys, policy)).rejects.toThrow();
  });

  it("rejects a nonce mismatch after cryptographic verification", async () => {
    const signed = await token(currentPrivateKey, { nonce: "replayed-nonce" });
    await expect(verifyInboundOidcToken(signed, rotatingKeys, policy)).rejects.toBeInstanceOf(InboundOidcClaimError);
  });

  it("requires azp to identify this client when the token has multiple audiences", async () => {
    const absent = await token(currentPrivateKey, { audience: [clientId, "other-client"] });
    const wrong = await token(currentPrivateKey, {
      audience: [clientId, "other-client"],
      authorizedParty: "other-client",
    });
    const correct = await token(currentPrivateKey, {
      audience: [clientId, "other-client"],
      authorizedParty: clientId,
    });

    await expect(verifyInboundOidcToken(absent, rotatingKeys, policy)).rejects.toBeInstanceOf(InboundOidcClaimError);
    await expect(verifyInboundOidcToken(wrong, rotatingKeys, policy)).rejects.toBeInstanceOf(InboundOidcClaimError);
    await expect(verifyInboundOidcToken(correct, rotatingKeys, policy)).resolves.toMatchObject({ azp: clientId });
  });
});
