import { escapeHtml, wrapEmailLayout } from "./base-layout";

export interface PasswordResetEmailVariables {
  firstName?: string | null;
  resetLink: string;
  expiresInMinutes?: number;
  ipAddress?: string | null;
}

export function renderPasswordResetEmail(variables: PasswordResetEmailVariables): {
  subject: string;
  html: string;
  text: string;
} {
  const name = variables.firstName ? variables.firstName : "there";
  const minutes = variables.expiresInMinutes || 15;
  const link = variables.resetLink;

  const ipNotice = variables.ipAddress
    ? `<p style="margin: 0 0 16px 0; color: #64748b; font-size: 13px;">Request initiated from IP: <code>${escapeHtml(variables.ipAddress)}</code></p>`
    : "";

  const contentHtml = `
    <p style="margin: 0 0 16px 0;">Hello ${escapeHtml(name)},</p>
    <p style="margin: 0 0 16px 0;">
      We received a request to reset the password for your UniERP account. Click the button below to choose a new, secure password.
    </p>
    ${ipNotice}
    <p style="margin: 0 0 16px 0; color: #b45309; font-size: 14px; background-color: #fef3c7; padding: 12px; border-radius: 6px; border: 1px solid #fde68a;">
      &#9888; This reset link is single-use and will expire in <strong>${minutes} minutes</strong>.
    </p>
  `;

  const secondaryText = `
    If you did not request a password reset, you can safely disregard this email. Your password will remain unchanged.<br><br>
    Button not working? Paste this link into your browser:<br>
    <a href="${escapeHtml(link)}" style="color: #2563eb; text-decoration: underline;">${escapeHtml(link)}</a>
  `;

  const html = wrapEmailLayout({
    previewText: "Reset your UniERP password",
    title: "Reset your password",
    contentHtml,
    ctaButton: {
      text: "Reset Password",
      url: link,
    },
    secondaryText,
    footerNotes: "For security, never forward this email to anyone.",
  });

  const text = `Hello ${name},\n\nWe received a request to reset the password for your UniERP account.\n\nReset your password here:\n${link}\n\nThis link will expire in ${minutes} minutes.\n\nIf you did not request this, please ignore this email.`;

  return {
    subject: "Reset your UniERP password",
    html,
    text,
  };
}
