#!/usr/bin/env node
/**
 * idp/scripts/rehearse-idp-key-rotation.mjs
 *
 * Operational IdP Key Rotation & Dual-JWKS Verification Rehearsal (FND-P0-003)
 *
 * Asserts:
 * 1. Cryptographic RS256 keypair generation with high-entropy keys.
 * 2. ID token issuance under current primary key (kid: key-active-01).
 * 3. Dual-key JWKS publishing: staging key-active-02 while keeping key-active-01 active.
 * 4. Zero-downtime token verification: both legacy and newly issued tokens verify cleanly.
 * 5. Primary key rollover: new tokens signed by key-active-02.
 * 6. Graceful retirement of key-active-01 after TTL expiry.
 */

import { generateKeyPair, exportJWK, SignJWT, jwtVerify, createLocalJWKSet } from "jose";

export async function rehearseKeyRotation() {
  console.log("===============================================================================");
  console.log(" UniERP IdP Operational Key Rotation Rehearsal (FND-P0-003)");
  console.log("===============================================================================\n");

  // Step 1: Initial State - Key 1 is active
  console.log("[1/5] Generating initial RS256 keypair (key-2026-q1)...");
  const key1 = await generateKeyPair("RS256", { modulusLength: 2048 });
  const jwk1 = await exportJWK(key1.publicKey);
  jwk1.kid = "key-2026-q1";
  jwk1.alg = "RS256";
  jwk1.use = "sig";

  const initialJwks = { keys: [jwk1] };
  let jwksResolver = createLocalJWKSet(initialJwks);

  // Issue token 1 using Key 1
  const token1 = await new SignJWT({
    sub: "usr-admin-01",
    tenantId: "tenant-acme",
    email: "admin@acme.corp",
  })
    .setProtectedHeader({ alg: "RS256", kid: "key-2026-q1" })
    .setIssuer("https://idp.unierp.internal")
    .setAudience("https://api.unierp.internal")
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(key1.privateKey);

  const verify1 = await jwtVerify(token1, jwksResolver, {
    issuer: "https://idp.unierp.internal",
    audience: "https://api.unierp.internal",
  });
  console.log(`[PASS] Token 1 successfully verified with Key 1 (kid=${verify1.protectedHeader.kid}).`);

  // Step 2: Key Rotation Staging - Generate Key 2 & Publish Dual JWKS
  console.log("\n[2/5] Generating successor keypair (key-2026-q2) and publishing dual-key JWKS...");
  const key2 = await generateKeyPair("RS256", { modulusLength: 2048 });
  const jwk2 = await exportJWK(key2.publicKey);
  jwk2.kid = "key-2026-q2";
  jwk2.alg = "RS256";
  jwk2.use = "sig";

  // Dual JWKS contains BOTH Key 1 and Key 2
  const dualJwks = { keys: [jwk1, jwk2] };
  jwksResolver = createLocalJWKSet(dualJwks);

  // Step 3: Zero-downtime verification under Dual JWKS
  console.log("[3/5] Testing dual-key verification for concurrent inflight sessions...");
  // Token 1 (signed by old Key 1) must still verify
  const verify1Dual = await jwtVerify(token1, jwksResolver, {
    issuer: "https://idp.unierp.internal",
    audience: "https://api.unierp.internal",
  });
  console.log(`[PASS] Inflight Token 1 successfully verified under dual JWKS (kid=${verify1Dual.protectedHeader.kid}).`);

  // Issue new token 2 using Key 2
  const token2 = await new SignJWT({
    sub: "usr-admin-02",
    tenantId: "tenant-acme",
    email: "operator@acme.corp",
  })
    .setProtectedHeader({ alg: "RS256", kid: "key-2026-q2" })
    .setIssuer("https://idp.unierp.internal")
    .setAudience("https://api.unierp.internal")
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(key2.privateKey);

  // Token 2 (signed by new Key 2) must verify cleanly
  const verify2Dual = await jwtVerify(token2, jwksResolver, {
    issuer: "https://idp.unierp.internal",
    audience: "https://api.unierp.internal",
  });
  console.log(`[PASS] New Token 2 successfully verified under dual JWKS (kid=${verify2Dual.protectedHeader.kid}).`);

  // Step 4: Promote Key 2 to Sole Primary and Retire Key 1
  console.log("\n[4/5] Retiring Key 1 after graceful TTL drain window...");
  const retiredJwks = { keys: [jwk2] };
  jwksResolver = createLocalJWKSet(retiredJwks);

  // Token 2 continues to verify
  const verify2Retired = await jwtVerify(token2, jwksResolver, {
    issuer: "https://idp.unierp.internal",
    audience: "https://api.unierp.internal",
  });
  console.log(`[PASS] Token 2 verified with Key 2 on newly consolidated JWKS (kid=${verify2Retired.protectedHeader.kid}).`);

  // Step 5: Verify Revocation / Rejection of Stale Key 1 Tokens
  console.log("\n[5/5] Asserting fail-closed rejection of retired Key 1 tokens...");
  let rejected = false;
  try {
    await jwtVerify(token1, jwksResolver, {
      issuer: "https://idp.unierp.internal",
      audience: "https://api.unierp.internal",
    });
  } catch (err) {
    rejected = true;
    console.log(`[PASS] Token signed with retired Key 1 correctly rejected: ${err.message}`);
  }

  if (!rejected) {
    throw new Error("Security Failure: Token signed by retired key was accepted after revocation");
  }

  console.log("\n===============================================================================");
  console.log(" ✅ IdP Operational Key Rotation Rehearsal Passed with 100% Zero-Downtime!");
  console.log("===============================================================================\n");
}

rehearseKeyRotation().catch((err) => {
  console.error(`❌ Key rotation rehearsal failed: ${err.message}`);
  process.exit(1);
});
