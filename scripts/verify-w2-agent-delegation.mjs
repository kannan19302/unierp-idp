/**
 * Live end-to-end verification of W2's agent delegation (RFC 8693 token
 * exchange).
 *
 * Prerequisites: idp on :3005, fixture tenant/user/sessions present, plus:
 *
 *   UPDATE oauth_clients SET grant_types = array_append(grant_types,
 *     'urn:ietf:params:oauth:grant-type:token-exchange')
 *   WHERE client_id = 'unierp-tenant-apps';
 *   INSERT INTO agent_definitions (id, tenant_id, name, allowed_permissions,
 *     status, updated_at)
 *   VALUES ('agent-e2e-invoice','tnt-e2e','Invoice Agent',
 *     ARRAY['finance.invoice.read'],'ACTIVE',now());
 *   INSERT INTO agent_definitions (id, tenant_id, name, allowed_permissions,
 *     status, updated_at)
 *   VALUES ('agent-e2e-disabled','tnt-e2e','Disabled Agent',
 *     ARRAY['finance.invoice.read'],'DISABLED',now());
 */
import { createHash, randomBytes } from "node:crypto";
import { SignJWT, decodeJwt } from "jose";

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

function pkce() {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

async function getUserAccessToken(sid, permissions) {
  const { verifier, challenge } = pkce();
  const authRes = await fetch(
    `${ISSUER}/oidc/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "unierp-tenant-apps",
      redirect_uri: "http://localhost:4003/auth/callback",
      scope: "openid profile email tenant erp.read",
      code_challenge: challenge,
      code_challenge_method: "S256",
    })}`,
    {
      redirect: "manual",
      headers: { cookie: `auth_token=${await sessionCookie({ sid, permissions })}` },
    },
  );
  const code = new URL(authRes.headers.get("location")).searchParams.get("code");
  const tokenRes = await fetch(`${ISSUER}/oidc/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      grant_type: "authorization_code",
      code,
      redirect_uri: "http://localhost:4003/auth/callback",
      code_verifier: verifier,
      client_id: "unierp-tenant-apps",
    }),
  });
  return tokenRes.json();
}

async function exchange(subjectToken, agentId) {
  const res = await fetch(`${ISSUER}/oidc/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: subjectToken,
      agent_id: agentId,
      client_id: "unierp-tenant-apps",
    }),
  });
  return res.json();
}

console.log("\n=== W2: Agent token exchange — happy path ===");
const user1 = await getUserAccessToken("sess-e2e-agent1", [
  "finance.invoice.read",
  "hr.employee.read",
]);
check("obtained a user access token", !!user1.access_token, user1.error ?? "");

const grant1 = await exchange(user1.access_token, "agent-e2e-invoice");
check("token exchange succeeded", !!grant1.access_token, grant1.error ?? "");
check(
  "issued_token_type is an access token",
  grant1.issued_token_type === "urn:ietf:params:oauth:token-type:access_token",
);
check("agent token TTL is minutes, not the user's own", grant1.expires_in <= 300);

if (grant1.access_token) {
  const agentClaims = decodeJwt(grant1.access_token);
  check("agent token carries act.agentId", agentClaims.act?.agentId === "agent-e2e-invoice");
  check("agent token carries the same sub as the delegating user", agentClaims.sub === "usr-e2e");
  check(
    "agent token permissions are the intersection, not the full user set",
    Array.isArray(agentClaims.permissions) &&
      agentClaims.permissions.includes("finance.invoice.read") &&
      !agentClaims.permissions.includes("hr.employee.read"),
    JSON.stringify(agentClaims.permissions),
  );
  check("agent token sid matches the delegating user's session (revocation chain)", agentClaims.sid === "sess-e2e-agent1");
}

console.log("\n=== W2 NEGATIVE: agent cannot obtain more than the user currently holds ===");
// Token issuance re-derives permissions from the DATABASE (AuthService.
// resolveRolesAndPermissions) on every mint — never from whatever the session
// cookie claims. So simulating "the user was demoted" means actually changing
// the role row, not forging a smaller permission list into the cookie.
const { execSync } = await import("node:child_process");
const demote =
  `docker exec postgres psql -U unerp -d unerp_dev -c ` +
  `"SELECT set_config('app.current_tenant_id','tnt-e2e',false); ` +
  `UPDATE roles SET permissions='[\\"saas.read\\"]' WHERE id='role-e2e';"`;
const restore =
  `docker exec postgres psql -U unerp -d unerp_dev -c ` +
  `"SELECT set_config('app.current_tenant_id','tnt-e2e',false); ` +
  `UPDATE roles SET permissions='[\\"finance.invoice.read\\",\\"saas.read\\"]' WHERE id='role-e2e';"`;

execSync(demote, { stdio: "pipe" });
const user2 = await getUserAccessToken("sess-e2e-agent2", []);
const grant2 = await exchange(user2.access_token, "agent-e2e-invoice");
execSync(restore, { stdio: "pipe" });

if (grant2.access_token) {
  const claims2 = decodeJwt(grant2.access_token);
  check(
    "agent receives an empty permission set once the role no longer grants it",
    Array.isArray(claims2.permissions) && claims2.permissions.length === 0,
    JSON.stringify(claims2.permissions),
  );
} else {
  check("agent receives an empty permission set once the role no longer grants it", false, grant2.error);
}

console.log("\n=== W2 NEGATIVE: an agent token can never obtain system.*/platform.* ===");
// The delegating user IS a control-plane holder here; the agent's own ceiling
// (enforced by the database CHECK constraint, which makes such a ceiling
// impossible to register) is what stops it, not the user's authority.
const providerUser = await getUserAccessToken("sess-e2e-agent3", [
  "system.tenant.read",
  "finance.invoice.read",
]);
const grant3 = await exchange(providerUser.access_token, "agent-e2e-invoice");
if (grant3.access_token) {
  const claims3 = decodeJwt(grant3.access_token);
  check(
    "even with a control-plane-holding delegator, the agent gets no system.* permission",
    !claims3.permissions.some((p) => p.startsWith("system.") || p.startsWith("platform.")),
    JSON.stringify(claims3.permissions),
  );
} else {
  check("token exchange succeeded for the control-plane-holding delegator", false, grant3.error);
}

console.log("\n=== W2 NEGATIVE: chained delegation is refused structurally ===");
if (grant1.access_token) {
  const chained = await exchange(grant1.access_token, "agent-e2e-invoice");
  check(
    "an agent token cannot itself be exchanged for another agent token",
    chained.error === "invalid_grant",
    JSON.stringify(chained),
  );
}

console.log("\n=== W2 NEGATIVE: unknown / disabled / cross-tenant agent ===");
const unknownAgent = await exchange(user1.access_token, "no-such-agent");
check("unknown agent id refused", unknownAgent.error === "invalid_grant");

const disabledAgent = await exchange(user1.access_token, "agent-e2e-disabled");
check("disabled agent refused", disabledAgent.error === "invalid_grant");

console.log("\n=== W2 NEGATIVE: revoking the delegating session kills the agent token ===");
if (grant1.access_token) {
  const beforeLogout = await fetch(`${ISSUER}/oidc/userinfo`, {
    headers: { authorization: `Bearer ${grant1.access_token}` },
  });
  check("agent token works before logout", beforeLogout.status === 200, `status ${beforeLogout.status}`);

  await fetch(
    `${ISSUER}/oidc/end_session?client_id=unierp-tenant-apps&post_logout_redirect_uri=${encodeURIComponent("http://localhost:4000/")}`,
    { redirect: "manual", headers: { cookie: `auth_token=${await sessionCookie({ sid: "sess-e2e-agent1" })}` } },
  );

  const afterLogout = await fetch(`${ISSUER}/oidc/userinfo`, {
    headers: { authorization: `Bearer ${grant1.access_token}` },
  });
  check(
    "revoking the delegating user's session kills the agent token in the same instant — no separate revocation path needed",
    afterLogout.status === 401,
    `status ${afterLogout.status}`,
  );
}

console.log(`\n${"=".repeat(60)}`);
console.log(`PASSED ${pass.length}   FAILED ${fail.length}`);
if (fail.length) {
  console.log("\nFailures:");
  for (const f of fail) console.log("  - " + f);
}
process.exit(fail.length ? 1 : 0);
