import { escapeHtml, wrapEmailLayout } from "./base-layout";

export interface WelcomeEmailVariables {
  firstName?: string | null;
  organizationName?: string | null;
  workspaceUrl: string;
  setupUrl?: string | null;
}

export function renderWelcomeEmail(variables: WelcomeEmailVariables): {
  subject: string;
  html: string;
  text: string;
} {
  const name = variables.firstName ? variables.firstName : "there";
  const org = variables.organizationName ? variables.organizationName : "your organization";
  const actionUrl = variables.setupUrl || variables.workspaceUrl;

  const contentHtml = `
    <p style="margin: 0 0 16px 0;">Hello ${escapeHtml(name)},</p>
    <p style="margin: 0 0 16px 0;">
      Welcome to <strong>UniERP</strong>! Your workspace for <strong>${escapeHtml(org)}</strong> is ready to power your enterprise operations.
    </p>
    <p style="margin: 0 0 20px 0;">
      Here are a few quick steps to get you up and running right away:
    </p>

    <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-bottom: 24px; border-collapse: separate; border-spacing: 0 10px;">
      <tr>
        <td style="width: 36px; vertical-align: top; padding-right: 12px;">
          <div style="width: 28px; height: 28px; border-radius: 50%; background-color: #dbeafe; color: #1d4ed8; text-align: center; line-height: 28px; font-weight: 700; font-size: 13px;">1</div>
        </td>
        <td style="vertical-align: top;">
          <strong style="color: #0f172a; font-size: 14px;">Complete Setup Wizard</strong><br>
          <span style="color: #64748b; font-size: 13px;">Configure your company details, fiscal calendar, and organizational defaults.</span>
        </td>
      </tr>
      <tr>
        <td style="width: 36px; vertical-align: top; padding-right: 12px;">
          <div style="width: 28px; height: 28px; border-radius: 50%; background-color: #dbeafe; color: #1d4ed8; text-align: center; line-height: 28px; font-weight: 700; font-size: 13px;">2</div>
        </td>
        <td style="vertical-align: top;">
          <strong style="color: #0f172a; font-size: 14px;">Invite Your Team</strong><br>
          <span style="color: #64748b; font-size: 13px;">Assign roles (Admin, Finance, Sales, HR, Inventory) with fine-grained permissions.</span>
        </td>
      </tr>
      <tr>
        <td style="width: 36px; vertical-align: top; padding-right: 12px;">
          <div style="width: 28px; height: 28px; border-radius: 50%; background-color: #dbeafe; color: #1d4ed8; text-align: center; line-height: 28px; font-weight: 700; font-size: 13px;">3</div>
        </td>
        <td style="vertical-align: top;">
          <strong style="color: #0f172a; font-size: 14px;">Explore Enterprise Modules</strong><br>
          <span style="color: #64748b; font-size: 13px;">Access General Ledger, CRM pipelines, Supply Chain, and Automated Billing.</span>
        </td>
      </tr>
    </table>
  `;

  const secondaryText = `
    Need guidance? Visit our <a href="https://docs.unierp.com" target="_blank" style="color: #2563eb; text-decoration: underline;">Documentation Center</a> or contact our enterprise team at <a href="mailto:support@unierp.com" style="color: #2563eb; text-decoration: underline;">support@unierp.com</a>.
  `;

  const html = wrapEmailLayout({
    previewText: `Welcome to UniERP! Your ${org} workspace is ready.`,
    title: "Welcome to UniERP",
    contentHtml,
    ctaButton: {
      text: "Launch Workspace",
      url: actionUrl,
    },
    secondaryText,
    footerNotes: "You received this email because you signed up for an account on UniERP.",
  });

  const text = `Hello ${name},\n\nWelcome to UniERP! Your workspace for ${org} is ready.\n\nQuick start:\n1. Complete your setup wizard\n2. Invite your team members\n3. Explore enterprise modules\n\nLaunch your workspace now:\n${actionUrl}\n\nSupport: support@unierp.com | Documentation: https://docs.unierp.com`;

  return {
    subject: `Welcome to UniERP — Let's get started with ${org}`,
    html,
    text,
  };
}
