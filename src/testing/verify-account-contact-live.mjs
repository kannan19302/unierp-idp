import { randomBytes } from "node:crypto";
import { SignJWT } from "jose";

const issuer = process.env.CONTACT_VERIFY_ISSUER || "http://localhost:3005";
const mailpit = process.env.CONTACT_VERIFY_MAILPIT || "http://localhost:8025";
const secret = process.env.NEXTAUTH_SECRET;
const sessionId = process.env.CONTACT_VERIFY_SESSION_ID;
const userId = process.env.CONTACT_VERIFY_USER_ID || "usr-e2e";
const tenantId = process.env.CONTACT_VERIFY_TENANT_ID || "tnt-e2e";
const primaryEmail = process.env.CONTACT_VERIFY_PRIMARY_EMAIL || "e2e@acme.test";
const recoveryEmail = process.env.CONTACT_VERIFY_EMAIL;

if (!secret || !sessionId || !recoveryEmail) {
  throw new Error("NEXTAUTH_SECRET, CONTACT_VERIFY_SESSION_ID and CONTACT_VERIFY_EMAIL are required");
}

const authToken = await new SignJWT({
  userId,
  tenantId,
  email: primaryEmail,
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

const added = await post("/oidc/account/contact/add", {
  email: recoveryEmail,
  label: "Live recovery inbox",
});
if (!added.id || added.verifiedAt) throw new Error("Recovery contact was not created in pending state");

const pendingHtml = await accountHtml();
if (
  !pendingHtml.includes("Contact methods") ||
  !pendingHtml.includes("Add recovery email") ||
  !pendingHtml.includes(recoveryEmail) ||
  !pendingHtml.includes("Verification pending") ||
  !pendingHtml.includes(`data-contact-resend=\"${added.id}\"`) ||
  !pendingHtml.includes(`data-contact-remove=\"${added.id}\"`)
) {
  throw new Error("Pending recovery contact controls were not rendered in Account Center");
}

const message = await waitForMessage(recoveryEmail);
if (message.Subject !== "Verify your UniERP recovery email") {
  throw new Error(`Unexpected verification subject: ${message.Subject}`);
}
const verificationUrl = `${message.Text || ""}\n${message.HTML || ""}`.match(
  /https?:\/\/[^\s<]+\/oidc\/account\/contact\/verify\?token=[A-Za-z0-9_-]{40,64}/,
)?.[0];
if (!verificationUrl) throw new Error("Mailpit message did not contain a verification URL");

const verified = await fetch(verificationUrl, { redirect: "manual" });
if (
  verified.status !== 302 ||
  !verified.headers.get("location")?.includes("success=Recovery%20email%20verified")
) {
  throw new Error("First recovery-email verification did not succeed");
}

const verifiedHtml = await accountHtml();
const contactPosition = verifiedHtml.indexOf(recoveryEmail);
if (
  contactPosition < 0 ||
  !verifiedHtml.slice(contactPosition, contactPosition + 500).includes("Verified") ||
  verifiedHtml.includes(`data-contact-resend=\"${added.id}\"`)
) {
  throw new Error("Verified recovery contact state was not rendered correctly");
}

const replay = await fetch(verificationUrl, { redirect: "manual" });
if (
  replay.status !== 302 ||
  !replay.headers.get("location")?.includes("error=Verification%20link%20is%20invalid%20or%20expired")
) {
  throw new Error("Consumed verification link was not rejected on replay");
}

const removed = await post("/oidc/account/contact/remove", { contactId: added.id });
if (!removed.deleted) throw new Error("Verified recovery contact could not be removed");
const removedHtml = await accountHtml();
if (removedHtml.includes(recoveryEmail)) throw new Error("Removed recovery contact still rendered in Account Center");

console.log(JSON.stringify({
  accountCenterControls: true,
  contactCreatedPending: true,
  emailQueuedAndDelivered: true,
  hashedOneTimeVerification: true,
  verifiedStateRendered: true,
  replayRejected: true,
  contactRemoved: true,
  recoveryEmail,
  contactId: added.id,
  mailpitMessageId: message.ID,
}));

async function accountHtml() {
  const response = await fetch(`${issuer}/oidc/account`, { headers: { cookie } });
  const html = await response.text();
  if (!response.ok) throw new Error(`Account Center failed (${response.status})`);
  return html;
}

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

async function waitForMessage(address) {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    const listResponse = await fetch(`${mailpit}/api/v1/messages`);
    const list = await listResponse.json();
    const summary = list.messages?.find((candidate) =>
      candidate.Subject === "Verify your UniERP recovery email" &&
      candidate.To?.some((recipient) => recipient.Address.toLowerCase() === address.toLowerCase()),
    );
    if (summary) {
      const detailResponse = await fetch(`${mailpit}/api/v1/message/${summary.ID}`);
      if (!detailResponse.ok) throw new Error("Mailpit message detail could not be read");
      return detailResponse.json();
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error("Recovery verification email was not delivered to Mailpit within 20 seconds");
}
