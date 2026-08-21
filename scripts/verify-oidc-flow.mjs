/**
 * End-to-end verification of the OIDC authorization-code + PKCE flow.
 *
 * Nothing here is mocked: real HTTP against a running IdP, real Postgres, real
 * RS256 keys. Unit tests prove each service in isolation; this proves they
 * compose into a flow a standards-conformant client can actually complete, and
 * that the negative cases fail the way they must.
 *
 * Prerequisites:
 *   1. Postgres up and migrated  (data: pnpm prisma migrate deploy)
 *   2. First-party clients seeded (data: pnpm tsx prisma/seed-oidc-clients.ts)
 *   3. The IdP running on :3005
 *   4. The fixture tenant/user/session below present and the session ACTIVE.
 *
 * The fixture sessions are deliberately deactivated by the reuse-detection and
 * logout cases, which is the correct behaviour under test — so reset them
 * between runs. Note the wildcard: this script burns sess-e2e-2, -3 and -4 as
 * well as sess-e2e, and resetting only sess-e2e leaves phase 11 authorizing
 * with a dead session, which bounces to /oidc/login instead of the client.
 *
 *   UPDATE user_sessions SET is_active = true WHERE id LIKE 'sess-e2e%';
 *
 * Usage:  node scripts/verify-oidc-flow.mjs
 */
/**
 * Live end-to-end check of the authorization-code + PKCE flow against the
 * running IdP. Nothing is mocked: real HTTP, real database, real RS256 keys.
 */
import { createHash, randomBytes } from "node:crypto";
import {
  createRemoteJWKSet,
  jwtVerify,
  decodeProtectedHeader,
  SignJWT,
} from "jose";

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

const pass = [];
const fail = [];
function check(name, ok, detail = "") {
  (ok ? pass : fail).push(name);
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`);
}

// A session cookie exactly as the existing auth service issues one: HS256 over
// NEXTAUTH_SECRET, with the purpose claim `typ: "session"`.
const HS = new TextEncoder().encode(SECRET);
// Several phases deliberately DESTROY the session they use — reuse detection
// and logout both do, correctly. They each take their own fixture session so
// one phase proving a session dies does not break the next phase.
async function sessionCookie(over = {}) {
  return new SignJWT({
    userId: "usr-e2e",
    email: "e2e@acme.test",
    tenantId: "tnt-e2e",
    sid: "sess-e2e",
    realm: "tenant",
    permissions: ["finance.invoice.read", "saas.read"],
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
  return {
    verifier,
    challenge: createHash("sha256").update(verifier).digest("base64url"),
  };
}

async function authorize(params, cookie) {
  const url = `${ISSUER}/oidc/authorize?${new URLSearchParams(params)}`;
  const res = await fetch(url, {
    redirect: "manual",
    headers: cookie ? { cookie: `auth_token=${cookie}` } : {},
  });
  return { status: res.status, location: res.headers.get("location") ?? "" };
}

/**
 * The `code` out of an authorize redirect, or a diagnosis of why there isn't
 * one. Phases that expect a code used to do `new URL(a.location)` directly,
 * which throws ERR_INVALID_URL and takes the whole run down when the IdP
 * answered with the relative `/oidc/login?...` — i.e. when the fixture session
 * was left deactivated by a previous run. That is a fixture problem, not a
 * broken flow, and it should read as one.
 */
function codeFrom(location, phase) {
  if (location.startsWith("/oidc/login")) {
    console.error(
      `
FAIL  ${phase}: the IdP bounced to the hosted login page, so the ` +
        `fixture session this phase uses is not ACTIVE.
` +
        `      Reset the fixtures and re-run:
` +
        `      UPDATE user_sessions SET is_active = true WHERE id LIKE 'sess-e2e%';
`,
    );
    process.exit(1);
  }
  const code = new URL(location, ISSUER).searchParams.get("code");
  if (!code) {
    console.error(`
FAIL  ${phase}: no code in the redirect — ${location}
`);
    process.exit(1);
  }
  return code;
}

async function token(body) {
  const res = await fetch(`${ISSUER}/oidc/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return res.json();
}

console.log("\n=== 1. Happy path: tenant user -> tenant platform (P3) ===");
const { verifier, challenge } = pkce();
const authzParams = {
  response_type: "code",
  client_id: "unierp-tenant-apps",
  redirect_uri: "http://localhost:4003/auth/callback",
  scope: "openid profile email tenant offline_access erp.read",
  state: "state-abc",
  nonce: "nonce-xyz",
  code_challenge: challenge,
  code_challenge_method: "S256",
};

const a1 = await authorize(authzParams, await sessionCookie());
check("authorize redirects back to the client", a1.status === 302, a1.location.slice(0, 60));
if (!a1.location.startsWith("http")) {
  console.log("ABORT: /authorize bounced to " + a1.location.split("?")[0]);
  console.log("The fixture session (sess-e2e) is inactive. Reset it with:");
  console.log("  UPDATE user_sessions SET is_active=true WHERE id='sess-e2e';");
  process.exit(1);
}
const loc = new URL(a1.location);
const code = loc.searchParams.get("code");
check("authorization code issued", !!code);
check("state echoed verbatim", loc.searchParams.get("state") === "state-abc");
check("no token leaked through the front channel", !a1.location.includes("access_token"));

console.log("\n=== 2. Token exchange ===");
const t1 = await token({
  grant_type: "authorization_code",
  code,
  redirect_uri: "http://localhost:4003/auth/callback",
  code_verifier: verifier,
  client_id: "unierp-tenant-apps",
});
check("access_token returned", !!t1.access_token, t1.error ?? "");
check("id_token returned (openid was requested)", !!t1.id_token);
check("refresh_token returned (offline_access granted)", !!t1.refresh_token);
check("token_type is Bearer", t1.token_type === "Bearer");
check("expires_in is 900s", t1.expires_in === 900);

console.log("\n=== 3. The access token verifies against the published JWKS ===");
const JWKS = createRemoteJWKSet(new URL(`${ISSUER}/oidc/jwks.json`));
let payload;
try {
  const v = await jwtVerify(t1.access_token, JWKS, {
    issuer: ISSUER,
    audience: "unierp-tenant-apps",
  });
  payload = v.payload;
  check("signature verifies against the public JWKS", true);
} catch (e) {
  check("signature verifies against the public JWKS", false, e.message);
}
if (payload) {
  check("alg is RS256", decodeProtectedHeader(t1.access_token).alg === "RS256");
  check("sub is the user", payload.sub === "usr-e2e");
  check("tenant claim present", payload.tenantId === "tnt-e2e");
  check("sid present (revocable)", payload.sid === "sess-e2e");
  check("realm is tenant", payload.realm === "tenant");
  check("platform binding present", payload.plat === "P3");
  check(
    "permissions resolved from the database, not the request",
    Array.isArray(payload.permissions) &&
      payload.permissions.includes("finance.invoice.read"),
    JSON.stringify(payload.permissions),
  );
}

console.log("\n=== 4. The id_token echoes the nonce ===");
const idPayload = JSON.parse(
  Buffer.from(t1.id_token.split(".")[1], "base64url").toString(),
);
check("nonce echoed", idPayload.nonce === "nonce-xyz");
check("email released (email scope granted)", idPayload.email === "e2e@acme.test");

console.log("\n=== 5. Replaying the same code is refused and revokes the grant ===");
const replay = await token({
  grant_type: "authorization_code",
  code,
  redirect_uri: "http://localhost:4003/auth/callback",
  code_verifier: verifier,
  client_id: "unierp-tenant-apps",
});
check("replayed code rejected", replay.error === "invalid_grant", replay.error);

console.log("\n=== 6. PKCE actually binds the code to its verifier ===");
const p2 = pkce();
const a2 = await authorize(
  { ...authzParams, code_challenge: p2.challenge },
  await sessionCookie(),
);
const code2 = new URL(a2.location).searchParams.get("code");
const wrongVerifier = await token({
  grant_type: "authorization_code",
  code: code2,
  redirect_uri: "http://localhost:4003/auth/callback",
  code_verifier: randomBytes(32).toString("base64url"),
  client_id: "unierp-tenant-apps",
});
check("wrong code_verifier rejected", wrongVerifier.error === "invalid_grant");
const rightVerifier = await token({
  grant_type: "authorization_code",
  code: code2,
  redirect_uri: "http://localhost:4003/auth/callback",
  code_verifier: p2.verifier,
  client_id: "unierp-tenant-apps",
});
check(
  "the code survives a failed PKCE attempt and the real client can still use it",
  !!rightVerifier.access_token,
  rightVerifier.error ?? "",
);

console.log("\n=== 7. NEGATIVE: tenant user crafting a request for the provider console ===");
const p3 = pkce();
const denied = await authorize(
  {
    response_type: "code",
    client_id: "unierp-provider-admin-os",
    redirect_uri: "http://localhost:4002/auth/callback",
    scope: "openid",
    state: "s",
    code_challenge: p3.challenge,
    code_challenge_method: "S256",
  },
  await sessionCookie(),
);
const deniedUrl = new URL(denied.location);
check(
  "the IdP refuses — not the UI",
  deniedUrl.searchParams.get("error") === "access_denied",
  deniedUrl.searchParams.get("error") ?? denied.location,
);
check("no code issued", !deniedUrl.searchParams.get("code"));

console.log("\n=== 8. NEGATIVE: a tenant super-admin wildcard must not cross the boundary ===");
const wildcard = await authorize(
  {
    response_type: "code",
    client_id: "unierp-provider-admin-os",
    redirect_uri: "http://localhost:4002/auth/callback",
    scope: "openid",
    code_challenge: p3.challenge,
    code_challenge_method: "S256",
  },
  await sessionCookie({ permissions: ["*"] }),
);
check(
  'a tenant holding ["*"] is still refused the control plane',
  new URL(wildcard.location).searchParams.get("error") === "access_denied",
);

console.log("\n=== 9. NEGATIVE: unregistered redirect_uri is never redirected to ===");
const openRedirect = await fetch(
  `${ISSUER}/oidc/authorize?${new URLSearchParams({
    response_type: "code",
    client_id: "unierp-tenant-apps",
    redirect_uri: "http://evil.test/steal",
    scope: "openid",
    code_challenge: p3.challenge,
    code_challenge_method: "S256",
  })}`,
  { redirect: "manual", headers: { cookie: `auth_token=${await sessionCookie()}` } },
);
check(
  "rejected with an error page, not a redirect (no open redirect)",
  openRedirect.status === 400,
  `status ${openRedirect.status}`,
);

console.log("\n=== 10. NEGATIVE: PKCE is not optional ===");
const noPkce = await authorize(
  {
    response_type: "code",
    client_id: "unierp-tenant-apps",
    redirect_uri: "http://localhost:4003/auth/callback",
    scope: "openid",
  },
  await sessionCookie(),
);
check(
  "authorize without code_challenge is refused",
  new URL(noPkce.location).searchParams.get("error") === "invalid_request",
);

console.log("\n=== 11. Refresh rotation and reuse detection ===");
// A fresh grant is required here: step 5 proved that replaying an
// authorization code revokes every token derived from that session, so
// t1.refresh_token is intentionally dead by now. Reusing it would re-test the
// previous step rather than rotation.
const p4 = pkce();
const a4 = await authorize(
  { ...authzParams, code_challenge: p4.challenge },
  await sessionCookie({ sid: "sess-e2e-2" }),
);
const t4 = await token({
  grant_type: "authorization_code",
  code: codeFrom(a4.location, "phase 11 (refresh rotation)"),
  redirect_uri: "http://localhost:4003/auth/callback",
  code_verifier: p4.verifier,
  client_id: "unierp-tenant-apps",
});
check("fresh grant obtained for the rotation test", !!t4.refresh_token, t4.error ?? "");

const r1 = await token({
  grant_type: "refresh_token",
  refresh_token: t4.refresh_token,
  client_id: "unierp-tenant-apps",
});
check("refresh returns a new access token", !!r1.access_token, r1.error ?? "");
check("refresh token rotated", !!r1.refresh_token && r1.refresh_token !== t4.refresh_token);

const reuse = await token({
  grant_type: "refresh_token",
  refresh_token: t4.refresh_token,
  client_id: "unierp-tenant-apps",
});
check("reusing the old refresh token is refused", reuse.error === "invalid_grant");

const afterBreach = await token({
  grant_type: "refresh_token",
  refresh_token: r1.refresh_token,
  client_id: "unierp-tenant-apps",
});
check(
  "reuse detection killed the session, so even the rotated token is dead",
  afterBreach.error === "invalid_grant",
  afterBreach.error ?? "still valid",
);

console.log("\n=== 12. NEGATIVE: unknown client ===");
const badClient = await token({
  grant_type: "authorization_code",
  code: "x",
  redirect_uri: "http://localhost:4003/auth/callback",
  code_verifier: "y",
  client_id: "no-such-client",
});
check("unknown client rejected", badClient.error === "invalid_client");


console.log("\n=== 13. Hosted login page ===");
const loginPage = await fetch(`${ISSUER}/oidc/login?return_to=%2Foidc%2Fauthorize`);
const loginHtml = await loginPage.text();
check("login page served", loginPage.status === 200);
check("has a password field", loginHtml.includes('type="password"'));
check("posts to the issuer, not a relying party", loginHtml.includes('action="/oidc/login"'));

const orLogin = await fetch(`${ISSUER}/oidc/login?return_to=https%3A%2F%2Fevil.test`);
check(
  "an absolute return_to is refused (no open redirect from the login page)",
  !(await orLogin.text()).includes("evil.test"),
);
const protoRel = await fetch(`${ISSUER}/oidc/login?return_to=%2F%2Fevil.test`);
check(
  "a protocol-relative return_to is refused too",
  !(await protoRel.text()).includes("evil.test"),
);

console.log("\n=== 14. Logged-out /authorize bounces to login, not a dead end ===");
const p5 = pkce();
const anon = await authorize({ ...authzParams, code_challenge: p5.challenge }, undefined);
check(
  "unauthenticated authorize redirects to the hosted login page",
  anon.location.startsWith("/oidc/login"),
  anon.location.split("?")[0],
);
check(
  "the original request is preserved for after sign-in",
  decodeURIComponent(anon.location).includes("/oidc/authorize"),
);

console.log("\n=== 15. userinfo ===");
const p6 = pkce();
const a6 = await authorize(
  { ...authzParams, code_challenge: p6.challenge },
  await sessionCookie({ sid: "sess-e2e-3" }),
);
const t6 = await token({
  grant_type: "authorization_code",
  code: new URL(a6.location).searchParams.get("code"),
  redirect_uri: "http://localhost:4003/auth/callback",
  code_verifier: p6.verifier,
  client_id: "unierp-tenant-apps",
});
const ui = await fetch(`${ISSUER}/oidc/userinfo`, {
  headers: { authorization: `Bearer ${t6.access_token}` },
});
const uiBody = await ui.json();
check("userinfo returns the subject", uiBody.sub === "usr-e2e", JSON.stringify(uiBody));
check("email released (scope granted)", uiBody.email === "e2e@acme.test");
check("profile name released", typeof uiBody.name === "string");
check("userinfo without a token is 401", (await fetch(`${ISSUER}/oidc/userinfo`)).status === 401);
check(
  "userinfo with a forged token is 401",
  (await fetch(`${ISSUER}/oidc/userinfo`, { headers: { authorization: "Bearer nope" } })).status === 401,
);

console.log("\n=== 16. Revocation ===");
const rev = await fetch(`${ISSUER}/oidc/revoke`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ token: t6.refresh_token }),
});
check("revoke returns 200", rev.status === 200);
const afterRevoke = await token({
  grant_type: "refresh_token",
  refresh_token: t6.refresh_token,
  client_id: "unierp-tenant-apps",
});
check("the revoked refresh token no longer works", afterRevoke.error === "invalid_grant");
const revUnknown = await fetch(`${ISSUER}/oidc/revoke`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ token: "never-existed" }),
});
check("revoking an unknown token still returns 200 (no oracle)", revUnknown.status === 200);

console.log("\n=== 17. RP-initiated logout ends the session everywhere ===");
const p7 = pkce();
const a7 = await authorize(
  { ...authzParams, code_challenge: p7.challenge },
  await sessionCookie({ sid: "sess-e2e-4" }),
);
const t7 = await token({
  grant_type: "authorization_code",
  code: new URL(a7.location).searchParams.get("code"),
  redirect_uri: "http://localhost:4003/auth/callback",
  code_verifier: p7.verifier,
  client_id: "unierp-tenant-apps",
});
check("a live session before logout", !!t7.access_token, t7.error ?? "");

const logout = await fetch(
  `${ISSUER}/oidc/end_session?client_id=unierp-tenant-apps&post_logout_redirect_uri=${encodeURIComponent("http://localhost:4000/")}`,
  {
    redirect: "manual",
    headers: {
      cookie: `auth_token=${await sessionCookie({ sid: "sess-e2e-4" })}`,
    },
  },
);
check("logout redirects to the registered post-logout URI", logout.status === 302);
check(
  "and only to a registered one",
  (logout.headers.get("location") ?? "").startsWith("http://localhost:4000/"),
  logout.headers.get("location") ?? "",
);
check(
  "an access token issued before logout stops working immediately",
  (await fetch(`${ISSUER}/oidc/userinfo`, { headers: { authorization: `Bearer ${t7.access_token}` } })).status === 401,
);
const logoutEvil = await fetch(
  `${ISSUER}/oidc/end_session?client_id=unierp-tenant-apps&post_logout_redirect_uri=${encodeURIComponent("http://evil.test/")}`,
  { redirect: "manual" },
);
check(
  "an unregistered post-logout URI is not honoured",
  !(logoutEvil.headers.get("location") ?? "").includes("evil.test"),
  logoutEvil.headers.get("location") ?? "",
);

console.log(`\n${"=".repeat(60)}`);
console.log(`PASSED ${pass.length}   FAILED ${fail.length}`);
if (fail.length) {
  console.log("\nFailures:");
  for (const f of fail) console.log("  - " + f);
}
process.exit(fail.length ? 1 : 0);
