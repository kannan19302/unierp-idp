import { escapeHtml, wrapEmailLayout } from "./base-layout";

export interface LoginAlertEmailVariables {
  firstName?: string | null;
  device?: string | null;
  location?: string | null;
  ipAddress?: string | null;
  timestamp?: string | null;
  securityUrl?: string | null;
}

export function renderLoginAlertEmail(variables: LoginAlertEmailVariables): {
  subject: string;
  html: string;
  text: string;
} {
  const name = variables.firstName ? variables.firstName : "there";
  const device = variables.device || "Unknown device";
  const location = variables.location || "Unknown location";
  const ip = variables.ipAddress || "Unknown IP";
  const time = variables.timestamp || new Date().toUTCString();
  const securityUrl = variables.securityUrl || "https://app.unierp.com/settings/security";

  const contentHtml = `
    <p style="margin: 0 0 16px 0;">Hello ${escapeHtml(name)},</p>
    <p style="margin: 0 0 16px 0;">
      A new sign-in to your UniERP account was detected from an unrecognized device or IP address.
    </p>

    <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="margin: 20px 0; background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; font-size: 13px;">
      <tr>
        <td style="padding: 10px 16px; border-bottom: 1px solid #e2e8f0; font-weight: 600; color: #475569; width: 100px;">Device:</td>
        <td style="padding: 10px 16px; border-bottom: 1px solid #e2e8f0; color: #0f172a;">${escapeHtml(device)}</td>
      </tr>
      <tr>
        <td style="padding: 10px 16px; border-bottom: 1px solid #e2e8f0; font-weight: 600; color: #475569;">Location:</td>
        <td style="padding: 10px 16px; border-bottom: 1px solid #e2e8f0; color: #0f172a;">${escapeHtml(location)}</td>
      </tr>
      <tr>
        <td style="padding: 10px 16px; border-bottom: 1px solid #e2e8f0; font-weight: 600; color: #475569;">IP Address:</td>
        <td style="padding: 10px 16px; border-bottom: 1px solid #e2e8f0; color: #0f172a;"><code>${escapeHtml(ip)}</code></td>
      </tr>
      <tr>
        <td style="padding: 10px 16px; font-weight: 600; color: #475569;">Time:</td>
        <td style="padding: 10px 16px; color: #0f172a;">${escapeHtml(time)}</td>
      </tr>
    </table>

    <p style="margin: 0 0 16px 0; color: #dc2626; font-size: 14px;">
      <strong>If this was not you:</strong> Please secure your account immediately by resetting your password and revoking active sessions.
    </p>
  `;

  const html = wrapEmailLayout({
    previewText: `Security Alert: New sign-in to your UniERP account from ${device}`,
    title: "New sign-in detected",
    contentHtml,
    ctaButton: {
      text: "Review Account Security",
      url: securityUrl,
    },
    footerNotes: "This security alert was sent automatically to protect your UniERP account.",
  });

  const text = `Hello ${name},\n\nA new sign-in was detected for your UniERP account:\n\nDevice: ${device}\nLocation: ${location}\nIP: ${ip}\nTime: ${time}\n\nIf this was not you, please secure your account immediately:\n${securityUrl}`;

  return {
    subject: "Security Alert: New sign-in to your UniERP account",
    html,
    text,
  };
}
