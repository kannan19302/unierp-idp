import { createHash, randomBytes } from "node:crypto";
import { SignJWT } from "jose";

const issuer = process.env.POLICY_VERIFY_ISSUER || "http://localhost:3005";
const secret = process.env.NEXTAUTH_SECRET;
const sessionId = process.env.POLICY_VERIFY_SESSION_ID;
const userId = process.env.POLICY_VERIFY_USER_ID || "usr-e2e";
const tenantId = process.env.POLICY_VERIFY_TENANT_ID || "tnt-e2e";
const email = process.env.POLICY_VERIFY_EMAIL || "e2e@acme.test";

if (!secret || !sessionId) {
  throw new Error(
    "NEXTAUTH_SECRET and POLICY_VERIFY_SESSION_ID are required for the live policy check",
  );
}

const cookie = await new SignJWT({
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

const verifier = `policy-${randomBytes(28).toString("base64url")}`;
const challenge = createHash("sha256").update(verifier).digest("base64url");
const redirectUri = "http://localhost:4003/auth/callback";
const authorizationUrl = `${issuer}/oidc/authorize?${new URLSearchParams({
  response_type: "code",
  client_id: "unierp-tenant-apps",
  redirect_uri: redirectUri,
  scope: "openid profile email tenant offline_access",
  code_challenge: challenge,
  code_challenge_method: "S256",
})}`;

const authorization = await fetch(authorizationUrl, {
  redirect: "manual",
  headers: { cookie: `auth_token=${cookie}` },
});
const location = authorization.headers.get("location");
const code = location ? new URL(location, issuer).searchParams.get("code") : null;
if (!code) {
  throw new Error(
    `Authorization did not return a code (status ${authorization.status}, location ${location || "none"})`,
  );
}

const tokenResponse = await fetch(`${issuer}/oidc/token`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier,
    client_id: "unierp-tenant-apps",
  }),
});
const tokens = await tokenResponse.json();
if (!tokenResponse.ok || !tokens.access_token) {
  throw new Error(
    `Token exchange failed (${tokenResponse.status}): ${tokens.error || "unknown error"}`,
  );
}

const response = await fetch(`${issuer}/api/v1/auth/platforms`, {
  headers: { authorization: `Bearer ${tokens.access_token}` },
});
const body = await response.json();
if (!response.ok) {
  throw new Error(
    `Platform policy request failed (${response.status}): ${body.message || body.code || "unknown error"}`,
  );
}

const platforms = Array.isArray(body.platforms) ? body.platforms : [];
const codes = platforms.map((platform) => platform.code).sort();
const baseline = ["P3", "P4", "P6", "P7", "P8", "P9", "P10"];
const missing = baseline.filter((codeValue) => !codes.includes(codeValue));
const malformed = platforms.filter(
  (platform) =>
    !["VISIBLE_ENABLED", "VISIBLE_DISABLED"].includes(platform.visibility) ||
    typeof platform.launchAllowed !== "boolean" ||
    !Array.isArray(platform.reasonCodes),
);

if (missing.length || codes.includes("P2") || codes.includes("P5") || malformed.length) {
  throw new Error(
    `Unexpected policy result: codes=${JSON.stringify(codes)}, missing=${JSON.stringify(missing)}, malformed=${malformed.length}`,
  );
}

let preferenceSync = null;
if (process.env.POLICY_VERIFY_PREFERENCES === "true") {
  const { idpPrisma, runWithTenantSession } = await import("@kannan19302/database");
  const inTenant = (operation) => runWithTenantSession({ tenantId, userId }, operation);
  const user = await inTenant(() => idpPrisma.user.findUnique({
    where: { id: userId },
    select: { preferences: true },
  }));
  if (!user) throw new Error(`Preference verification user ${userId} was not found`);

  const originalPreferences = user.preferences;
  const probe = {
    favoriteCodes: ["P3"],
    recent: [{ code: "P7", openedAt: new Date().toISOString() }],
  };

  try {
    const update = await fetch(`${issuer}/api/v1/auth/me`, {
      method: "PATCH",
      headers: {
        authorization: `Bearer ${tokens.access_token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ preferences: { platformWizard: probe } }),
    });
    if (!update.ok) {
      const detail = await update.text();
      throw new Error(`Preference update failed (${update.status}): ${detail}`);
    }

    const profileResponse = await fetch(`${issuer}/api/v1/auth/me`, {
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });
    const profile = await profileResponse.json();
    const saved = profile?.preferences?.platformWizard;
    if (!profileResponse.ok || saved?.favoriteCodes?.[0] !== "P3" || saved?.recent?.[0]?.code !== "P7") {
      throw new Error(`Preference read-after-write failed (${profileResponse.status})`);
    }
    preferenceSync = { status: update.status, readAfterWrite: true, restored: true };
  } finally {
    await inTenant(() => idpPrisma.user.update({
      where: { id: userId },
      data: { preferences: originalPreferences },
    }));
  }
}

console.log(
  JSON.stringify({
    status: response.status,
    policyVersion: body.policyVersion,
    evaluatedAt: body.evaluatedAt,
    requestIdPresent: Boolean(body.requestId),
    codes,
    malformed: malformed.length,
    preferenceSync,
  }),
);
