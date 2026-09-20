/**
 * UniERP System Email Base Layout
 * Email-client compatible responsive table-based layout with inline styling,
 * dark mode support, and strict HTML escaping.
 */

export function escapeHtml(str: unknown): string {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export interface EmailLayoutOptions {
  previewText?: string;
  title: string;
  contentHtml: string;
  ctaButton?: {
    text: string;
    url: string;
  };
  secondaryText?: string;
  footerNotes?: string;
}

export function wrapEmailLayout(options: EmailLayoutOptions): string {
  const preview = options.previewText
    ? `<div style="display:none;font-size:1px;color:#ffffff;line-height:1px;max-height:0px;max-width:0px;opacity:0;overflow:hidden;">${escapeHtml(options.previewText)}</div>`
    : "";

  const cta = options.ctaButton
    ? `
      <table role="presentation" border="0" cellpadding="0" cellspacing="0" style="margin: 28px 0 24px 0;">
        <tr>
          <td align="center">
            <a href="${escapeHtml(options.ctaButton.url)}" target="_blank" rel="noopener noreferrer" style="display: inline-block; padding: 14px 32px; background-color: #2563eb; color: #ffffff; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; font-size: 15px; font-weight: 600; text-decoration: none; border-radius: 8px; box-shadow: 0 2px 4px rgba(37, 99, 235, 0.2); letter-spacing: 0.2px;">
              ${escapeHtml(options.ctaButton.text)}
            </a>
          </td>
        </tr>
      </table>
    `
    : "";

  const secondary = options.secondaryText
    ? `
      <div style="margin-top: 20px; padding: 16px; background-color: #f8fafc; border-radius: 6px; border: 1px solid #e2e8f0; font-size: 13px; line-height: 1.6; color: #64748b; word-break: break-all;">
        ${options.secondaryText}
      </div>
    `
    : "";

  const footerNotes = options.footerNotes
    ? `<p style="margin: 0 0 12px 0; font-size: 12px; color: #94a3b8; line-height: 1.5;">${escapeHtml(options.footerNotes)}</p>`
    : "";

  return `<!DOCTYPE html>
<html lang="en" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="format-detection" content="telephone=no, date=no, address=no, email=no">
  <title>${escapeHtml(options.title)}</title>
  <!--[if mso]>
  <noscript>
    <xml>
      <o:OfficeDocumentSettings>
        <o:PixelsPerInch>96</o:PixelsPerInch>
      </o:OfficeDocumentSettings>
    </xml>
  </noscript>
  <![endif]-->
  <style>
    body {
      margin: 0;
      padding: 0;
      width: 100% !important;
      -webkit-text-size-adjust: 100%;
      -ms-text-size-adjust: 100%;
      background-color: #f1f5f9;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    }
    @media only screen and (max-width: 620px) {
      .email-container {
        width: 100% !important;
        margin: 0 auto !important;
        border-radius: 0 !important;
      }
      .email-body {
        padding: 24px 20px !important;
      }
    }
    @media (prefers-color-scheme: dark) {
      .dark-bg { background-color: #0f172a !important; }
      .dark-card { background-color: #1e293b !important; border-color: #334155 !important; }
      .dark-text { color: #f8fafc !important; }
      .dark-muted { color: #94a3b8 !important; }
      .dark-box { background-color: #0f172a !important; border-color: #334155 !important; color: #94a3b8 !important; }
    }
  </style>
</head>
<body style="margin: 0; padding: 32px 0; background-color: #f1f5f9; -webkit-font-smoothing: antialiased;">
  ${preview}
  <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%">
    <tr>
      <td align="center" style="padding: 0 16px;">
        <!-- Header Branding -->
        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px; margin-bottom: 20px;">
          <tr>
            <td align="center" style="padding: 12px 0;">
              <table role="presentation" border="0" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="vertical-align: middle; padding-right: 10px;">
                    <div style="width: 36px; height: 36px; border-radius: 8px; background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%); text-align: center; line-height: 36px; color: #ffffff; font-size: 20px; font-weight: 700;">U</div>
                  </td>
                  <td style="vertical-align: middle;">
                    <span style="font-size: 22px; font-weight: 800; letter-spacing: -0.5px; color: #0f172a;">Uni<span style="color: #2563eb;">ERP</span></span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>

        <!-- Main Card Container -->
        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" class="email-container" style="max-width: 600px; background-color: #ffffff; border-radius: 12px; border: 1px solid #e2e8f0; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05); overflow: hidden;">
          <tr>
            <td class="email-body" style="padding: 40px 36px; font-size: 15px; line-height: 1.6; color: #334155; text-align: left;">
              <h1 style="margin: 0 0 20px 0; font-size: 24px; font-weight: 700; color: #0f172a; line-height: 1.3; letter-spacing: -0.3px;">
                ${escapeHtml(options.title)}
              </h1>
              
              ${options.contentHtml}

              ${cta}

              ${secondary}
            </td>
          </tr>
        </table>

        <!-- Footer -->
        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px; margin-top: 24px;">
          <tr>
            <td align="center" style="padding: 12px 24px; text-align: center;">
              ${footerNotes}
              <p style="margin: 0 0 8px 0; font-size: 12px; color: #94a3b8;">
                &copy; ${new Date().getFullYear()} UniERP Inc. All rights reserved.
              </p>
              <p style="margin: 0; font-size: 12px; color: #94a3b8;">
                <a href="https://unierp.com/security" target="_blank" style="color: #64748b; text-decoration: underline; margin: 0 8px;">Security</a> &bull;
                <a href="https://unierp.com/privacy" target="_blank" style="color: #64748b; text-decoration: underline; margin: 0 8px;">Privacy</a> &bull;
                <a href="https://unierp.com/support" target="_blank" style="color: #64748b; text-decoration: underline; margin: 0 8px;">Support</a>
              </p>
            </td>
          </tr>
        </table>

      </td>
    </tr>
  </table>
</body>
</html>`;
}
