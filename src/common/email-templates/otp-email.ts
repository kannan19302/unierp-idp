import { escapeHtml, wrapEmailLayout } from "./base-layout";

export interface OtpEmailVariables {
  code: string;
  expiresInMinutes?: number;
  recipientEmail?: string;
}

export function renderOtpEmail(variables: OtpEmailVariables): {
  subject: string;
  html: string;
  text: string;
} {
  const code = variables.code;
  const minutes = variables.expiresInMinutes || 5;

  const contentHtml = `
    <p style="margin: 0 0 16px 0;">Hello,</p>
    <p style="margin: 0 0 20px 0;">
      Use the following single-use verification code to complete your authentication with UniERP:
    </p>

    <!-- Code Display Box -->
    <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="margin: 24px 0;">
      <tr>
        <td align="center">
          <div style="display: inline-block; padding: 18px 36px; background-color: #f1f5f9; border: 2px dashed #cbd5e1; border-radius: 10px; font-family: 'SF Mono', SFMono-Regular, Consolas, 'Liberation Mono', Menlo, Courier, monospace; font-size: 32px; font-weight: 700; letter-spacing: 8px; color: #0f172a; text-align: center;">
            ${escapeHtml(code)}
          </div>
        </td>
      </tr>
    </table>

    <p style="margin: 0 0 16px 0; color: #64748b; font-size: 14px; text-align: center;">
      This code is valid for <strong>${minutes} minutes</strong>. Do not share this code with anyone.
    </p>
  `;

  const footerNotes = "If you didn't request this code, you can safely ignore this email. Someone may have entered your address by mistake.";

  const html = wrapEmailLayout({
    previewText: `Your UniERP verification code is ${code}`,
    title: "Verification Code",
    contentHtml,
    footerNotes,
  });

  const text = `Your UniERP verification code is: ${code}\n\nThis code expires in ${minutes} minutes.\n\nIf you did not request this code, please ignore this email.`;

  return {
    subject: "Your UniERP verification code",
    html,
    text,
  };
}
