/**
 * The reusable part of the platform-credentials system: one entry per
 * integration/tunable "provider", each listing its editable fields. Adding a
 * new provider is just appending an object here — the service, admin API,
 * and SaaS Portal Settings UI all render generically off this list, no new
 * endpoints or components required.
 */
export interface CredentialFieldSpec {
  key: string;
  label: string;
  /** Encrypted at rest, masked in getMasked(), rendered as a password input. */
  sensitive: boolean;
  /** process.env fallback read when no DB row exists for this field. */
  envFallback?: string;
  required?: boolean;
}

export interface CredentialProviderSpec {
  provider: string;
  label: string;
  fields: CredentialFieldSpec[];
}

export const PLATFORM_CREDENTIAL_PROVIDERS: CredentialProviderSpec[] = [
  {
    provider: "google-oauth",
    label: "Google OAuth",
    fields: [
      {
        key: "enabled",
        label: "Enabled",
        sensitive: false,
        envFallback: "GOOGLE_OAUTH_ENABLED",
      },
      {
        key: "clientId",
        label: "Client ID",
        sensitive: false,
        envFallback: "GOOGLE_OAUTH_CLIENT_ID",
      },
      {
        key: "clientSecret",
        label: "Client Secret",
        sensitive: true,
        envFallback: "GOOGLE_OAUTH_CLIENT_SECRET",
      },
    ],
  },
  {
    provider: "microsoft-oauth",
    label: "Microsoft OAuth",
    fields: [
      {
        key: "enabled",
        label: "Enabled",
        sensitive: false,
        envFallback: "MICROSOFT_OAUTH_ENABLED",
      },
      {
        key: "clientId",
        label: "Client ID",
        sensitive: false,
        envFallback: "MICROSOFT_OAUTH_CLIENT_ID",
      },
      {
        key: "clientSecret",
        label: "Client Secret",
        sensitive: true,
        envFallback: "MICROSOFT_OAUTH_CLIENT_SECRET",
      },
      {
        key: "tenantId",
        label: "Tenant ID",
        sensitive: false,
        envFallback: "MICROSOFT_OAUTH_TENANT",
      },
    ],
  },
  {
    provider: "github-oauth",
    label: "GitHub OAuth",
    fields: [
      {
        key: "enabled",
        label: "Enabled",
        sensitive: false,
        envFallback: "GITHUB_OAUTH_ENABLED",
      },
      {
        key: "clientId",
        label: "Client ID",
        sensitive: false,
        envFallback: "GITHUB_OAUTH_CLIENT_ID",
      },
      {
        key: "clientSecret",
        label: "Client Secret",
        sensitive: true,
        envFallback: "GITHUB_OAUTH_CLIENT_SECRET",
      },
    ],
  },
  {
    provider: "stripe",
    label: "Stripe",
    fields: [
      {
        key: "secretKey",
        label: "Secret Key",
        sensitive: true,
        envFallback: "STRIPE_SECRET_KEY",
      },
      {
        key: "webhookSecret",
        label: "Webhook Signing Secret",
        sensitive: true,
        envFallback: "STRIPE_WEBHOOK_SECRET",
      },
    ],
  },
  {
    provider: "email-config",
    label: "Global Email Configuration",
    fields: [
      {
        key: "preferredProvider",
        label: "Active Email Provider (resend / brevo / smtp / sendgrid / postmark / auto)",
        sensitive: false,
        envFallback: "EMAIL_PROVIDER",
      },
      {
        key: "defaultFrom",
        label: "Default From Address",
        sensitive: false,
        envFallback: "EMAIL_FROM",
      },
      {
        key: "replyTo",
        label: "Default Reply-To Address",
        sensitive: false,
      },
    ],
  },
  {
    provider: "resend",
    label: "Resend Email API",
    fields: [
      {
        key: "apiKey",
        label: "API Key",
        sensitive: true,
        envFallback: "RESEND_API_KEY",
      },
      {
        key: "from",
        label: "Verified From Address",
        sensitive: false,
        envFallback: "EMAIL_FROM",
      },
    ],
  },
  {
    provider: "brevo",
    label: "Brevo Email API",
    fields: [
      {
        key: "apiKey",
        label: "API Key",
        sensitive: true,
        envFallback: "BREVO_API_KEY",
      },
      {
        key: "from",
        label: "Verified From Address",
        sensitive: false,
        envFallback: "EMAIL_FROM",
      },
    ],
  },
  {
    provider: "sendgrid",
    label: "SendGrid Email API",
    fields: [
      {
        key: "apiKey",
        label: "API Key",
        sensitive: true,
        envFallback: "SENDGRID_API_KEY",
      },
      {
        key: "from",
        label: "Verified From Address",
        sensitive: false,
        envFallback: "EMAIL_FROM",
      },
    ],
  },
  {
    provider: "postmark",
    label: "Postmark Email API",
    fields: [
      {
        key: "serverToken",
        label: "Server API Token",
        sensitive: true,
        envFallback: "POSTMARK_SERVER_TOKEN",
      },
      {
        key: "from",
        label: "Sender Signature / From Address",
        sensitive: false,
        envFallback: "EMAIL_FROM",
      },
    ],
  },
  {
    provider: "smtp",
    label: "SMTP / Custom Mail Server",
    fields: [
      {
        key: "host",
        label: "Host",
        sensitive: false,
        envFallback: "SMTP_HOST",
      },
      {
        key: "port",
        label: "Port",
        sensitive: false,
        envFallback: "SMTP_PORT",
      },
      {
        key: "user",
        label: "Username",
        sensitive: false,
        envFallback: "SMTP_USER",
      },
      {
        key: "password",
        label: "Password",
        sensitive: true,
        envFallback: "SMTP_PASSWORD",
      },
      {
        key: "from",
        label: "From Address",
        sensitive: false,
        envFallback: "SMTP_FROM",
      },
    ],
  },
  {
    provider: "web-push",
    label: "Web Push (VAPID)",
    fields: [
      {
        key: "publicKey",
        label: "Public Key",
        sensitive: false,
        envFallback: "VAPID_PUBLIC_KEY",
      },
      {
        key: "privateKey",
        label: "Private Key",
        sensitive: true,
        envFallback: "VAPID_PRIVATE_KEY",
      },
      {
        key: "subject",
        label: "Contact Subject (mailto: or URL)",
        sensitive: false,
        envFallback: "VAPID_SUBJECT",
      },
    ],
  },
  {
    provider: "object-storage",
    label: "Object Storage (S3-compatible)",
    fields: [
      {
        key: "endpoint",
        label: "Endpoint",
        sensitive: false,
        envFallback: "S3_ENDPOINT",
      },
      {
        key: "accessKey",
        label: "Access Key",
        sensitive: false,
        envFallback: "S3_ACCESS_KEY",
      },
      {
        key: "secretKey",
        label: "Secret Key",
        sensitive: true,
        envFallback: "S3_SECRET_KEY",
      },
      {
        key: "bucket",
        label: "Bucket",
        sensitive: false,
        envFallback: "S3_BUCKET",
      },
    ],
  },
  {
    provider: "sentry",
    label: "Sentry",
    fields: [
      { key: "dsn", label: "DSN", sensitive: true, envFallback: "SENTRY_DSN" },
    ],
  },
  {
    provider: "razorpay",
    label: "Razorpay",
    fields: [
      {
        key: "webhookSecret",
        label: "Webhook Secret",
        sensitive: true,
        envFallback: "RAZORPAY_WEBHOOK_SECRET",
      },
    ],
  },
  {
    provider: "captcha",
    label: "CAPTCHA",
    fields: [
      {
        key: "provider",
        label: "Provider (hcaptcha / recaptcha)",
        sensitive: false,
        envFallback: "CAPTCHA_PROVIDER",
      },
      {
        key: "siteKey",
        label: "Site Key",
        sensitive: false,
        envFallback: "CAPTCHA_SITE_KEY",
      },
      {
        key: "secretKey",
        label: "Secret Key",
        sensitive: true,
        envFallback: "CAPTCHA_SECRET_KEY",
      },
      {
        key: "threshold",
        label: "Score Threshold",
        sensitive: false,
        envFallback: "CAPTCHA_THRESHOLD",
      },
    ],
  },
];

export function findProviderSpec(
  provider: string,
): CredentialProviderSpec | undefined {
  return PLATFORM_CREDENTIAL_PROVIDERS.find((p) => p.provider === provider);
}
