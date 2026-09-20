import { escapeHtml, wrapEmailLayout } from "./base-layout";

export interface VerificationEmailVariables {
  firstName?: string | null;
  email?: string | null;
  verificationLink: string;
  expiresInHours?: number;
}

export function renderVerificationEmail(variables: VerificationEmailVariables): {
  subject: string;
  html: string;
  text: string;
} {
  const name = variables.firstName ? variables.firstName : "there";
  const hours = variables.expiresInHours || 24;
  const link = variables.verificationLink;

  const contentHtml = `
    <p style="margin: 0 0 16px 0;">Hello ${escapeHtml(name)},</p>
    <p style="margin: 0 0 16px 0;">
      Thank you for creating your UniERP account. To complete your setup and secure your new workspace, please verify your email address.
    </p>
    <p style="margin: 0 0 16px 0; color: #64748b; font-size: 14px;">
      This verification link is active for the next <strong>${hours} hours</strong>.
    </p>
  `;

  const secondaryText = `
    If the button above does not work, copy and paste this link into your browser:<br>
    <a href="${escapeHtml(link)}" style="color: #2563eb; text-decoration: underline;">${escapeHtml(link)}</a>
  `;

  const footerNotes = "If you didn't create a UniERP account, you can safely ignore this email.";

  const html = wrapEmailLayout({
    previewText: "Please verify your email address to get started with UniERP",
    title: "Verify your email address",
    contentHtml,
    ctaButton: {
      text: "Verify Email Address",
      url: link,
    },
    secondaryText,
    footerNotes,
  });

  const text = `Hello ${name},\n\nThank you for creating your UniERP account. Please verify your email address to complete your setup:\n\n${link}\n\nThis link will expire in ${hours} hours.\n\nIf you did not create a UniERP account, you can safely ignore this message.`;

  return {
    subject: "Verify your UniERP email address",
    html,
    text,
  };
}
