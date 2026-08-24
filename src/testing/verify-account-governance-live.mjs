import { randomBytes } from "node:crypto";
import { SignJWT } from "jose";

const issuer = process.env.GOVERNANCE_VERIFY_ISSUER || "http://localhost:3005";
const secret = process.env.NEXTAUTH_SECRET;
const sessionId = process.env.GOVERNANCE_VERIFY_SESSION_ID;
const userId = process.env.GOVERNANCE_VERIFY_USER_ID || "usr-e2e";
const tenantId = process.env.GOVERNANCE_VERIFY_TENANT_ID || "tnt-e2e";
const targetTenantId = process.env.GOVERNANCE_VERIFY_TARGET_TENANT_ID;
const email = process.env.GOVERNANCE_VERIFY_EMAIL || "e2e@acme.test";

if (!secret || !sessionId || !targetTenantId) {
  throw new Error("NEXTAUTH_SECRET, GOVERNANCE_VERIFY_SESSION_ID and GOVERNANCE_VERIFY_TARGET_TENANT_ID are required");
}

const authToken = await new SignJWT({
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
const cookie = `auth_token=${authToken}; oidc_csrf=${csrf}`;
const account = await fetch(`${issuer}/oidc/account`, { headers: { cookie } });
const html = await account.text();
for (const marker of [
  "Organizations",
  "Governance live target",
  "Primary email contact",
  "Portable identity export",
  "Request account deletion",
]) {
  if (!account.ok || !html.includes(marker)) {
    throw new Error(`Account Center governance marker was missing: ${marker}`);
  }
}

const exported = await post("/oidc/account/governance/privacy/export");
if (
  exported.data?.schemaVersion !== "unierp.subject-export.v1" ||
  exported.data?.account?.id !== userId ||
  JSON.stringify(exported.data).includes("passwordHash") ||
  JSON.stringify(exported.data).includes("publicKey")
) {
  throw new Error("Subject export was malformed or exposed credential material");
}

const deletion = await post("/oidc/account/governance/privacy/deletion/request", {
  reason: "Automated live governance verification",
});
if (deletion.status !== "PENDING" || !deletion.eligibleAt) {
  throw new Error("Deletion request did not enter the governed cooling-off state");
}
const cancellation = await post("/oidc/account/governance/privacy/deletion/cancel", {
  requestId: deletion.id,
});
if (cancellation.status !== "CANCELLED") {
  throw new Error("Deletion request cancellation failed");
}

const switched = await post("/oidc/account/governance/organization/switch", {
  targetTenantId,
});
if (!switched.switched || switched.returnTo !== "/oidc/account") {
  throw new Error("Verified organization switch did not issue a destination session");
}

console.log(JSON.stringify({
  accountCenterRendered: true,
  organizations: true,
  verifiedPrimaryContact: true,
  export: true,
  exportRedacted: true,
  deletionCoolingOff: true,
  deletionCancellation: true,
  organizationSwitch: true,
  exportJobId: exported.jobId,
  erasureRequestId: deletion.id,
}));

async function post(path, body = {}) {
  const response = await fetch(`${issuer}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie },
    body: JSON.stringify({ _csrf: csrf, ...body }),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(`${path} failed (${response.status}): ${payload.message || JSON.stringify(payload)}`);
  }
  return payload;
}
