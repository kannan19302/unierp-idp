import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
} from "node:crypto";
import { encodeCBOR } from "@levischuck/tiny-cbor";
import { SignJWT } from "jose";

const issuer = process.env.PASSKEY_VERIFY_ISSUER || "http://localhost:3005";
const secret = process.env.NEXTAUTH_SECRET;
const sessionId = process.env.PASSKEY_VERIFY_SESSION_ID;
const userId = process.env.PASSKEY_VERIFY_USER_ID || "usr-e2e";
const tenantId = process.env.PASSKEY_VERIFY_TENANT_ID || "tnt-e2e";
const email = process.env.PASSKEY_VERIFY_EMAIL || "e2e@acme.test";
const origin = process.env.PASSKEY_VERIFY_ORIGIN || "http://localhost:3005";
const rpId = process.env.WEBAUTHN_RP_ID || "localhost";

if (!secret || !sessionId) {
  throw new Error("NEXTAUTH_SECRET and PASSKEY_VERIFY_SESSION_ID are required");
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
const credentialId = randomBytes(32);
const credentialIdEncoded = credentialId.toString("base64url");
const { privateKey, publicKey } = generateKeyPairSync("ec", {
  namedCurve: "prime256v1",
});
const jwk = publicKey.export({ format: "jwk" });
if (!jwk.x || !jwk.y) throw new Error("P-256 public key export failed");

const registrationOptions = await post(
  "/oidc/passkeys/registration/options",
  { _csrf: csrf },
  cookie,
);
if (
  registrationOptions.options?.rp?.id !== rpId ||
  registrationOptions.options?.authenticatorSelection?.residentKey !== "required" ||
  registrationOptions.options?.authenticatorSelection?.userVerification !== "required"
) {
  throw new Error("Registration options did not enforce the expected RP and UV policy");
}

const registrationClientData = Buffer.from(JSON.stringify({
  type: "webauthn.create",
  challenge: registrationOptions.options.challenge,
  origin,
  crossOrigin: false,
}));
const coseKey = new Map([
  [1, 2],
  [3, -7],
  [-1, 1],
  [-2, Buffer.from(jwk.x, "base64url")],
  [-3, Buffer.from(jwk.y, "base64url")],
]);
const registrationAuthData = Buffer.concat([
  sha256(Buffer.from(rpId)),
  Buffer.from([0x45]),
  uint32(0),
  Buffer.alloc(16),
  uint16(credentialId.length),
  credentialId,
  Buffer.from(encodeCBOR(coseKey)),
]);
const attestationObject = encodeCBOR(new Map([
  ["fmt", "none"],
  ["attStmt", new Map()],
  ["authData", registrationAuthData],
]));

const registered = await post(
  "/oidc/passkeys/registration/verify",
  {
    _csrf: csrf,
    handle: registrationOptions.handle,
    name: "Automated live verifier",
    response: {
      id: credentialIdEncoded,
      rawId: credentialIdEncoded,
      type: "public-key",
      clientExtensionResults: {},
      response: {
        clientDataJSON: registrationClientData.toString("base64url"),
        attestationObject: Buffer.from(attestationObject).toString("base64url"),
        transports: ["internal"],
      },
    },
  },
  cookie,
);

const account = await fetch(`${issuer}/oidc/account`, {
  headers: { cookie },
});
const accountHtml = await account.text();
if (!account.ok || !accountHtml.includes("Automated live verifier")) {
  throw new Error(`Account Center did not render the enrolled passkey (${account.status})`);
}

const authenticationOptions = await post(
  "/oidc/passkeys/authentication/options",
  { _csrf: csrf, returnTo: "/oidc/account" },
  cookie,
);
if (authenticationOptions.options?.userVerification !== "required") {
  throw new Error("Authentication options did not require user verification");
}
const authenticationClientData = Buffer.from(JSON.stringify({
  type: "webauthn.get",
  challenge: authenticationOptions.options.challenge,
  origin,
  crossOrigin: false,
}));
const authenticationAuthData = Buffer.concat([
  sha256(Buffer.from(rpId)),
  Buffer.from([0x05]),
  uint32(1),
]);
const signature = sign(
  "sha256",
  Buffer.concat([authenticationAuthData, sha256(authenticationClientData)]),
  privateKey,
);
const assertion = {
  id: credentialIdEncoded,
  rawId: credentialIdEncoded,
  type: "public-key",
  clientExtensionResults: {},
  response: {
    authenticatorData: authenticationAuthData.toString("base64url"),
    clientDataJSON: authenticationClientData.toString("base64url"),
    signature: signature.toString("base64url"),
    userHandle: Buffer.from(userId).toString("base64url"),
  },
};
const authenticated = await post(
  "/oidc/passkeys/authentication/verify",
  { _csrf: csrf, handle: authenticationOptions.handle, response: assertion },
  cookie,
);
if (!authenticated.authenticated || authenticated.returnTo !== "/oidc/account") {
  throw new Error("Passkey assertion did not produce the expected authenticated redirect");
}

const replay = await fetch(`${issuer}/oidc/passkeys/authentication/verify`, {
  method: "POST",
  headers: { "content-type": "application/json", cookie },
  body: JSON.stringify({
    _csrf: csrf,
    handle: authenticationOptions.handle,
    response: assertion,
  }),
});
if (replay.status !== 400) {
  throw new Error(`Consumed passkey challenge replay returned ${replay.status}, expected 400`);
}

await post(
  "/oidc/passkeys/delete",
  { _csrf: csrf, passkeyId: registered.id },
  cookie,
);

console.log(JSON.stringify({
  registration: true,
  accountCenterRendered: true,
  authentication: true,
  userVerificationRequired: true,
  replayRejected: true,
  deletion: true,
  credentialId: credentialIdEncoded,
}));

async function post(path, body, requestCookie) {
  const response = await fetch(`${issuer}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie: requestCookie },
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(`${path} failed (${response.status}): ${payload.message || JSON.stringify(payload)}`);
  }
  return payload;
}

function sha256(value) {
  return createHash("sha256").update(value).digest();
}

function uint16(value) {
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16BE(value);
  return buffer;
}

function uint32(value) {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value);
  return buffer;
}
