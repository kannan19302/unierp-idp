export * from "./base-layout";
export * from "./verification-email";
export * from "./welcome-email";
export * from "./password-reset";
export * from "./login-alert";
export * from "./otp-email";

import {
  renderVerificationEmail,
  VerificationEmailVariables,
} from "./verification-email";
import { renderWelcomeEmail, WelcomeEmailVariables } from "./welcome-email";
import {
  renderPasswordResetEmail,
  PasswordResetEmailVariables,
} from "./password-reset";
import { renderLoginAlertEmail, LoginAlertEmailVariables } from "./login-alert";
import { renderOtpEmail, OtpEmailVariables } from "./otp-email";

export type SystemEmailTemplateKey =
  | "verification"
  | "welcome"
  | "password-reset"
  | "login-alert"
  | "otp";

export interface SystemTemplateMetadata {
  key: SystemEmailTemplateKey;
  name: string;
  description: string;
  category: "authentication" | "security" | "onboarding";
  sampleVariables: Record<string, any>;
}

export const SYSTEM_EMAIL_TEMPLATES: SystemTemplateMetadata[] = [
  {
    key: "verification",
    name: "Email Verification",
    description: "Sent immediately upon user registration with activation link",
    category: "authentication",
    sampleVariables: {
      firstName: "Alex",
      email: "alex.smith@example.com",
      verificationLink: "https://auth.unierp.com/verify-email?token=sample_token_12345",
      expiresInHours: 24,
    },
  },
  {
    key: "welcome",
    name: "Welcome to UniERP",
    description: "Sent after first successful login with onboarding quick-start guide",
    category: "onboarding",
    sampleVariables: {
      firstName: "Alex",
      organizationName: "Acme Innovations Ltd",
      workspaceUrl: "https://app.unierp.com",
      setupUrl: "https://app.unierp.com/setup",
    },
  },
  {
    key: "password-reset",
    name: "Password Reset",
    description: "Sent when user or admin requests a password reset link",
    category: "authentication",
    sampleVariables: {
      firstName: "Alex",
      resetLink: "https://auth.unierp.com/reset-password?token=sample_reset_67890",
      expiresInMinutes: 15,
      ipAddress: "198.51.100.42",
    },
  },
  {
    key: "login-alert",
    name: "Security Alert: New Sign-In",
    description: "Sent when an account is accessed from an unfamiliar IP or device",
    category: "security",
    sampleVariables: {
      firstName: "Alex",
      device: "Chrome 124 on macOS 14.4",
      location: "San Francisco, CA, United States",
      ipAddress: "198.51.100.42",
      timestamp: new Date().toUTCString(),
      securityUrl: "https://app.unierp.com/settings/security",
    },
  },
  {
    key: "otp",
    name: "One-Time Verification Code (OTP)",
    description: "Single-use 6-digit code for MFA or passwordless step-up verification",
    category: "authentication",
    sampleVariables: {
      code: "849201",
      expiresInMinutes: 5,
      recipientEmail: "alex.smith@example.com",
    },
  },
];

/**
 * Universal renderer for all UniERP transactional email templates.
 */
export function renderEmailTemplate(
  template: SystemEmailTemplateKey,
  variables: Record<string, any>,
): {
  subject: string;
  html: string;
  text: string;
} {
  switch (template) {
    case "verification":
      return renderVerificationEmail(variables as VerificationEmailVariables);
    case "welcome":
      return renderWelcomeEmail(variables as WelcomeEmailVariables);
    case "password-reset":
      return renderPasswordResetEmail(variables as PasswordResetEmailVariables);
    case "login-alert":
      return renderLoginAlertEmail(variables as LoginAlertEmailVariables);
    case "otp":
      return renderOtpEmail(variables as OtpEmailVariables);
    default:
      throw new Error(`Unknown email template: "${template}"`);
  }
}
