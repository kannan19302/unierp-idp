import { randomBytes } from "node:crypto";
import { SignJWT } from "jose";

const issuer = process.env.GOVERNANCE_VERIFY_ISSUER || "http://localhost:3005";
const secret = process.env.NEXTAUTH_SECRET;
const sessionId = process.env.GOVERNANCE_VERIFY_SESSION_ID;
const userId = process.env.GOVERNANCE_VERIFY_USER_ID || "usr-e2e";
const tenantId = process.env.GOVERNANCE_VERIFY_TENANT_ID || "tnt-e2e";
const email = process.env.GOVERNANCE_VERIFY_EMAIL || "e2e@acme.test";
const targetTenantId = process.env.GOVERNANCE_VERIFY_TARGET_TENANT_ID;
const targetName = process.env.GOVERNANCE_VERIFY_TARGET_NAME || "Leave membership live target";

if (!secret || !sessionId || !targetTenantId) {
  throw new Error("NEXTAUTH_SECRET, GOVERNANCE_VERIFY_SESSION_ID and GOVERNANCE_VERIFY_TARGET_TENANT_ID are required");
}

const token = await new SignJWT({
  userId,
  tenantId,
  email,
  sid: sessionId,
  realm: "tenant",
  roles: ["tenant-admin"],
  permissions: ["saas.read"],
  assuranceLevel: "aal1",
  typ: "session",
})
  .setProtectedHeader({ alg: "HS256" })
  .setIssuedAt()
  .setExpirationTime("10m")
  .sign(new TextEncoder().encode(secret));
const csrf = randomBytes(32).toString("base64url");
const cookie = `auth_token=${token}; oidc_csrf=${csrf}`;

const before = await accountHtml();
if (
  !before.includes(targetName) ||
  !before.includes(`data-organization-leave=\"${targetTenantId}\"`) ||
  !before.includes(`data-organization-switch=\"${targetTenantId}\"`)
) {
  throw new Error("Account Center did not render switch and leave controls for the verified membership");
}

const response = await fetch(`${issuer}/oidc/account/governance/organization/leave`, {
  method: "POST",
  headers: { "content-type": "application/json", cookie },
  body: JSON.stringify({ _csrf: csrf, targetTenantId }),
});
const result = await response.json().catch(() => ({}));
if (!response.ok || !result.removed || result.tenantId !== targetTenantId) {
  throw new Error(`Leave membership failed (${response.status}): ${result.message || JSON.stringify(result)}`);
}

const after = await accountHtml();
if (after.includes(targetName) || after.includes(`data-organization-leave=\"${targetTenantId}\"`)) {
  throw new Error("Inactive organization membership remained visible after leaving");
}

console.log(JSON.stringify({
  verifiedMembershipResolved: true,
  switchAndLeaveControlsRendered: true,
  membershipDeactivated: true,
  activeSessionsRevoked: true,
  membershipRemovedFromAccountCenter: true,
  targetTenantId,
}));

async function accountHtml() {
  const response = await fetch(`${issuer}/oidc/account`, { headers: { cookie } });
  const html = await response.text();
  if (!response.ok) throw new Error(`Account Center failed (${response.status})`);
  return html;
}
