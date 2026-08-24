import { Request, Response, NextFunction } from "express";
import crypto from "crypto";

const CSRF_COOKIE = "csrf_token";
const CSRF_HEADER = "x-csrf-token";
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

// The hosted IdP forms use a separate synchronizer-token implementation in
// LoginController: an HttpOnly, SameSite=Lax `oidc_csrf` cookie paired with a
// hidden `_csrf` field and constant-time verification. Ordinary API callers
// use the double-submit `csrf_token` cookie plus `x-csrf-token` header below.
//
// Browsers cannot attach a custom header to a native HTML form submission, so
// applying both mechanisms made every otherwise-valid hosted form fail before
// its controller-level CSRF check ran. Keep this list exact: a prefix match
// would accidentally exempt unrelated future OIDC routes.
const CONTROLLER_CSRF_PROTECTED_FORM_PATHS = new Set([
  "/oidc/account/unlink",
  "/oidc/login",
  "/oidc/login/mfa",
  "/oidc/register",
  "/oidc/forgot-password",
  "/oidc/reset-password",
  "/oidc/verify-email/resend",
  "/oidc/passkeys/registration/options",
  "/oidc/passkeys/registration/verify",
  "/oidc/passkeys/authentication/options",
  "/oidc/passkeys/authentication/verify",
  "/oidc/passkeys/delete",
  "/oidc/account/governance/organization/switch",
  "/oidc/account/governance/organization/leave",
  "/oidc/account/governance/privacy/export",
  "/oidc/account/governance/privacy/deletion/request",
  "/oidc/account/governance/privacy/deletion/cancel",
  "/oidc/account/contact/add",
  "/oidc/account/contact/resend",
  "/oidc/account/contact/remove",
]);

function generateCsrfToken(): string {
  return crypto.randomBytes(32).toString("hex");
}

export function csrfMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  let token = req.cookies?.[CSRF_COOKIE];

  if (!token) {
    token = generateCsrfToken();
    res.cookie(CSRF_COOKIE, token, {
      httpOnly: false,
      sameSite: "strict",
      secure: process.env.NODE_ENV === "production",
      path: "/",
    });
  }

  if (SAFE_METHODS.has(req.method)) {
    return next();
  }

  // A Bearer token is explicit request authority, not an ambient browser
  // credential. Cross-site HTML forms cannot set Authorization and scripted
  // cross-origin requests must pass CORS preflight, so applying a cookie
  // double-submit check here blocks conforming OIDC/native clients without
  // mitigating CSRF. JwtAuthGuard still validates the token after middleware;
  // this exemption does not make a forged Bearer value authoritative.
  const authorization = req.headers.authorization;
  if (typeof authorization === "string" && /^Bearer\s+\S+$/i.test(authorization)) {
    return next();
  }

  const path = req.path || req.url;

  // Provider callbacks carry their own cryptographic/authentication proof and
  // never use browser cookies. Applying double-submit CSRF would make these
  // server-to-server endpoints impossible to call.
  if (path.startsWith("/api/v1/email/webhooks/")) {
    return next();
  }

  if (CONTROLLER_CSRF_PROTECTED_FORM_PATHS.has(path)) {
    return next();
  }

  // Skip CSRF for public endpoints (web forms, RFQ bids)
  if (path.includes("/public/")) {
    return next();
  }

  // Skip CSRF for the programmatic OAuth 2.0 / OIDC protocol endpoints.
  //
  // CSRF protects against a request the browser makes with ambient authority —
  // a cookie it attaches automatically. The token endpoint has no ambient
  // authority to abuse: the caller must present an authorization code AND the
  // PKCE verifier that code was bound to (or a refresh token), none of which a
  // cross-site attacker can obtain or replay. It is also called server-to-server
  // and by native clients that have no cookie jar and no way to read a CSRF
  // cookie, so the check cannot be satisfied by a conformant OAuth client at
  // all — it would simply make the flow impossible rather than safer.
  //
  // Hosted browser forms are deliberately not listed here. Their exact paths
  // are delegated above to LoginController's synchronizer-token checks.
  const programmaticOidcEndpoints = [
    "/oidc/token",
    "/oidc/revoke",
    "/oidc/introspect",
    "/oidc/userinfo",
    "/.well-known/openid-configuration",
    "/oidc/jwks.json",
  ];
  if (programmaticOidcEndpoints.some((p) => path.endsWith(p))) {
    return next();
  }

  // Skip CSRF for the E-Commerce Storefront's public/unauthenticated routes
  // (apps/api/src/modules/ecommerce/ecommerce-public.controller.ts, mounted at
  // /store/:tenantSlug/*). These serve anonymous external customers who never
  // receive a session cookie or CSRF token in the first place — the same
  // documented exception as PublicTenantResolverGuard's bypass of
  // JwtAuthGuard/RbacGuard. Without this, cart/checkout writes from the public
  // storefront always 403 with "Invalid or missing CSRF token".
  if (path.startsWith("/api/v1/store/") || path.startsWith("/store/")) {
    return next();
  }

  // Skip CSRF for the CRM customer self-service portal (/portal/*). Like the
  // storefront above, portal sessions authenticate with a Bearer JWT
  // (`CustomerPortalAuthGuard`) instead of the httpOnly session cookie CSRF
  // protects — there is no ambient-cookie attack vector for a token the
  // browser must explicitly attach via `Authorization`, so the check is both
  // inapplicable and blocks legitimate portal writes (case creation, quote
  // accept/reject) that never receive a `csrf_token` cookie in the first place.
  if (path.startsWith("/api/v1/portal/") || path.startsWith("/portal/")) {
    return next();
  }

  const headerToken = req.headers[CSRF_HEADER] as string | undefined;
  if (!headerToken || headerToken !== token) {
    return res.status(403).json({ message: "Invalid or missing CSRF token" });
  }

  next();
}
