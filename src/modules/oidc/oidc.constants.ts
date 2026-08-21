/**
 * Authorization-server constants.
 *
 * Scopes here are deliberately coarse. Fine-grained authority stays in the
 * existing PERMISSION_REGISTRY (shared/src/permissions/registry.ts) — a token's
 * effective authority is the intersection:
 *
 *     scopes ∩ user permissions ∩ tenant entitlements
 *
 * Splitting it this way means a third-party app can be granted "read ERP data"
 * without the consent screen having to enumerate several hundred permission
 * strings, while the permission model stays the single source of truth for what
 * any given call is allowed to do.
 */

export const SCOPE = {
  /** Required by OIDC to get an id_token at all. */
  OPENID: "openid",
  PROFILE: "profile",
  EMAIL: "email",
  /** Tenant membership and the active tenant claim. */
  TENANT: "tenant",
  OFFLINE_ACCESS: "offline_access",

  ERP_READ: "erp.read",
  ERP_WRITE: "erp.write",
  MARKETPLACE_INSTALL: "marketplace.install",
  /** Only ever present on a delegated agent token (W2). */
  AGENT: "agent",
} as const;

export type Scope = (typeof SCOPE)[keyof typeof SCOPE];

export const ALL_SCOPES: string[] = Object.values(SCOPE);

/**
 * Scopes a first-party platform client may request without a consent screen.
 * `agent` is excluded on purpose: delegation is always an explicit act, never
 * something a platform picks up by default.
 */
export const FIRST_PARTY_DEFAULT_SCOPES: string[] = [
  SCOPE.OPENID,
  SCOPE.PROFILE,
  SCOPE.EMAIL,
  SCOPE.TENANT,
  SCOPE.OFFLINE_ACCESS,
  SCOPE.ERP_READ,
  SCOPE.ERP_WRITE,
];

export const GRANT_TYPE = {
  AUTHORIZATION_CODE: "authorization_code",
  REFRESH_TOKEN: "refresh_token",
  CLIENT_CREDENTIALS: "client_credentials",
  TOKEN_EXCHANGE: "urn:ietf:params:oauth:grant-type:token-exchange",
} as const;

export type GrantType = (typeof GRANT_TYPE)[keyof typeof GRANT_TYPE];

export const CLIENT_TYPE = {
  CONFIDENTIAL: "CONFIDENTIAL",
  PUBLIC: "PUBLIC",
} as const;

export const CLIENT_STATUS = {
  ACTIVE: "ACTIVE",
  SUSPENDED: "SUSPENDED",
  REVOKED: "REVOKED",
} as const;

/**
 * Token lifetimes.
 *
 * The access token is short because it is the only credential that is NOT
 * checked against the database on every request by relying parties — they
 * verify the signature offline against the JWKS. Fifteen minutes bounds how
 * long a stolen token is useful; the refresh token is the revocable half.
 */
export const TOKEN_TTL = {
  /** Authorization code — single use, exchanged within seconds in practice. */
  AUTHORIZATION_CODE_MS: 60_000,
  ACCESS_TOKEN_MS: 15 * 60_000,
  ID_TOKEN_MS: 15 * 60_000,
  REFRESH_TOKEN_MS: 30 * 24 * 60 * 60_000,
  /** Agent tokens are minutes, not hours — see W2. */
  AGENT_TOKEN_MS: 5 * 60_000,
} as const;

/** PKCE. S256 only; `plain` is rejected and the database enforces it too. */
export const PKCE_METHOD_S256 = "S256";

/**
 * OAuth 2.0 error codes (RFC 6749 §4.1.2.1 / §5.2). These are protocol values,
 * not prose: relying parties branch on them, so they must not be reworded.
 */
export const OAUTH_ERROR = {
  INVALID_REQUEST: "invalid_request",
  UNAUTHORIZED_CLIENT: "unauthorized_client",
  ACCESS_DENIED: "access_denied",
  UNSUPPORTED_RESPONSE_TYPE: "unsupported_response_type",
  INVALID_SCOPE: "invalid_scope",
  SERVER_ERROR: "server_error",
  INVALID_CLIENT: "invalid_client",
  INVALID_GRANT: "invalid_grant",
  UNSUPPORTED_GRANT_TYPE: "unsupported_grant_type",
  CONSENT_REQUIRED: "consent_required",
  LOGIN_REQUIRED: "login_required",
} as const;

/**
 * The ten platforms, as client ids. Platform binding on a client is what lets
 * /authorize refuse a token for a platform the user is not entitled to (W2),
 * rather than relying on the UI to hide a tile.
 */
export const PLATFORM_CLIENT_ID = {
  P1_MARKETING: "unierp-marketing-site",
  P2_PROVIDER_ADMIN: "unierp-provider-admin-os",
  P3_TENANT_APPS: "unierp-tenant-apps",
  P4_TENANT_SITES: "unierp-tenant-sites",
  P5_WEB_STUDIO: "unierp-web-studio",
  P6_TENANT_ADMIN: "unierp-tenant-admin",
  P7_MARKETPLACE: "unierp-marketplace",
  P8_DEVELOPER: "unierp-developer-platform",
  P9_MOBILE: "unierp-mobile",
  P10_DESKTOP: "unierp-desktop",
  WIZARD: "unierp-platform-wizard",
} as const;
