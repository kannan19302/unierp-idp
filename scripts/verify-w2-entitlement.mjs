/**
 * Live end-to-end verification of W2's platform entitlement.
 *
 * Prerequisites: idp running on :3005, migrations applied, seed-oidc-clients.ts
 * and seed-platform-entitlement.ts run, and the fixture tenant/user from
 * scripts/verify-oidc-flow.mjs present. Additionally requires:
 *
 *   INSERT INTO saas_plans (id, name, stripe_price_id, max_users, max_storage,
 *     features, is_public, status, created_at, updated_at)
 *   VALUES ('plan-business-e2e','Business','price_e2e_business',25,51200,
 *     '["erp","crm"]',true,'ACTIVE',now(),now());
 *   INSERT INTO tenant_subscriptions (id, tenant_id, plan_id, status,
 *     start_date, created_at, updated_at)
 *   VALUES ('tsub-e2e','tnt-e2e','plan-business-e2e','ACTIVE',now(),now(),now());
 */
import { SignJWT } from "jose";

const ISSUER = "http://localhost:3005";
const SECRET =
  // Must match the running IdP's signing secret, so it is read from the
  // environment first. The literal below is only a fallback for a dev IdP
  // started with this well-known fixture value; infra/.env generates a random
  // secret per machine (scripts/gen-dev-secrets.sh), and a hardcoded default
  // silently produces cookies the server refuses — which looks like a broken
  // session rather than a config mismatch.
  process.env.NEXTAUTH_SECRET ||
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const HS = new TextEncoder().encode(SECRET);

const pass = [];
const fail = [];
function check(name, ok, detail = "") {
  (ok ? pass : fail).push(name);
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`);
}

async function sessionCookie(over = {}) {
  return new SignJWT({
    userId: "usr-e2e",
    email: "e2e@acme.test",
    tenantId: "tnt-e2e",
    sid: "sess-e2e",
    realm: "tenant",
    permissions: ["finance.invoice.read", "saas.read"],
    roles: ["tenant-admin"],
    typ: "session",
    ...over,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(HS);
}

async function authorize(clientId, redirect, cookie) {
  const url = `${ISSUER}/oidc/authorize?${new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirect,
    scope: "openid",
    code_challenge: "x".repeat(43), // not exchanged in these checks
    code_challenge_method: "S256",
  })}`;
  const res = await fetch(url, {
    redirect: "manual",
    headers: cookie ? { cookie: `auth_token=${cookie}` } : {},
  });
  return { status: res.status, location: res.headers.get("location") ?? "" };
}

console.log("\n=== W2: Plan-gated platform (P5 Web Studio) ===");

// tnt-e2e's tenant_subscriptions row (seeded above) is on plan-business-e2e,
// which platform_grants does NOT yet grant P5 to.
const beforeGrant = await authorize(
  "unierp-web-studio",
  "http://localhost:4005/auth/callback",
  await sessionCookie(),
);
check(
  "no plan grant yet -> access_denied",
  new URL(beforeGrant.location).searchParams.get("error") === "access_denied",
  beforeGrant.location,
);

console.log("\n=== W2: /auth/platforms reflects entitlement, matching /oidc/authorize ===");
// Mint a real access token via the full flow to call /auth/platforms with.
const p = { verifier: "verifier-" + "x".repeat(34) };
const enc = new TextEncoder();
const digest = await crypto.subtle.digest("SHA-256", enc.encode(p.verifier));
const challenge = Buffer.from(digest).toString("base64url");

const authRes = await authorize2(challenge);
async function authorize2(codeChallenge) {
  const url = `${ISSUER}/oidc/authorize?${new URLSearchParams({
    response_type: "code",
    client_id: "unierp-tenant-apps",
    redirect_uri: "http://localhost:4003/auth/callback",
    scope: "openid profile email tenant erp.read",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  })}`;
  return fetch(url, {
    redirect: "manual",
    headers: { cookie: `auth_token=${await sessionCookie({ sid: "sess-e2e-w2" })}` },
  });
}
const code = new URL(authRes.headers.get("location")).searchParams.get("code");
const tokenRes = await fetch(`${ISSUER}/oidc/token`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    grant_type: "authorization_code",
    code,
    redirect_uri: "http://localhost:4003/auth/callback",
    code_verifier: p.verifier,
    client_id: "unierp-tenant-apps",
  }),
});
const tokens = await tokenRes.json();
check("obtained a token for /auth/platforms", !!tokens.access_token, tokens.error ?? "");

const platformsRes = await fetch(`${ISSUER}/api/v1/auth/platforms`, {
  headers: { authorization: `Bearer ${tokens.access_token}` },
});
const platformsBody = await platformsRes.json();
const codes = (platformsBody.platforms ?? []).map((x) => x.code).sort();
check(
  "wizard list includes the baseline tenant platforms",
  ["P3", "P4", "P6", "P7", "P8", "P9", "P10"].every((c) => codes.includes(c)),
  JSON.stringify(codes),
);
check("wizard list excludes P2 for a tenant user", !codes.includes("P2"));
check("wizard list excludes P5 before any plan grant", !codes.includes("P5"));

console.log("\n=== Granting P5 to the Business plan and re-checking ===");
const { execSync } = await import("node:child_process");
execSync(
  `docker exec postgres psql -U unerp -d unerp_dev -c "INSERT INTO platform_grants (id, subject_type, subject_id, platform_code, tenant_id) VALUES ('pg-e2e-p5','PLAN','plan-business-e2e','P5',NULL) ON CONFLICT DO NOTHING;"`,
  { stdio: "pipe" },
);

const afterGrant = await authorize(
  "unierp-web-studio",
  "http://localhost:4005/auth/callback",
  await sessionCookie({ sid: "sess-e2e-w2b" }),
);
check(
  "plan grant added -> authorize now succeeds",
  !!new URL(afterGrant.location).searchParams.get("code"),
  afterGrant.location,
);

const platformsRes2 = await fetch(`${ISSUER}/api/v1/auth/platforms`, {
  headers: { authorization: `Bearer ${tokens.access_token}` },
});
const codes2 = ((await platformsRes2.json()).platforms ?? [])
  .map((x) => x.code)
  .sort();
check(
  "P5 now appears in the wizard list with no code change, only data",
  codes2.includes("P5"),
  JSON.stringify(codes2),
);

console.log("\n=== Cleanup: revoke the plan grant, confirm P5 closes again ===");
execSync(
  `docker exec postgres psql -U unerp -d unerp_dev -c "DELETE FROM platform_grants WHERE id='pg-e2e-p5';"`,
  { stdio: "pipe" },
);
const afterRevoke = await authorize(
  "unierp-web-studio",
  "http://localhost:4005/auth/callback",
  await sessionCookie({ sid: "sess-e2e-w2c" }),
);
check(
  "revoking the plan grant closes P5 again",
  new URL(afterRevoke.location).searchParams.get("error") === "access_denied",
);

console.log("\n=== Cancelled subscription does not keep unlocking its plan ===");
execSync(
  `docker exec postgres psql -U unerp -d unerp_dev -c "INSERT INTO platform_grants (id, subject_type, subject_id, platform_code, tenant_id) VALUES ('pg-e2e-p5b','PLAN','plan-business-e2e','P5',NULL) ON CONFLICT DO NOTHING; UPDATE tenant_subscriptions SET status='CANCELED' WHERE tenant_id='tnt-e2e';"`,
  { stdio: "pipe" },
);
const cancelled = await authorize(
  "unierp-web-studio",
  "http://localhost:4005/auth/callback",
  await sessionCookie({ sid: "sess-e2e-w2d" }),
);
check(
  "a CANCELED subscription no longer grants its plan's platforms",
  new URL(cancelled.location).searchParams.get("error") === "access_denied",
);
execSync(
  `docker exec postgres psql -U unerp -d unerp_dev -c "UPDATE tenant_subscriptions SET status='ACTIVE' WHERE tenant_id='tnt-e2e'; DELETE FROM platform_grants WHERE id='pg-e2e-p5b';"`,
  { stdio: "pipe" },
);

console.log(`\n${"=".repeat(60)}`);
console.log(`PASSED ${pass.length}   FAILED ${fail.length}`);
if (fail.length) {
  console.log("\nFailures:");
  for (const f of fail) console.log("  - " + f);
}
process.exit(fail.length ? 1 : 0);
