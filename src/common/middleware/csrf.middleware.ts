import { Request, Response, NextFunction } from "express";
import crypto from "crypto";

const CSRF_COOKIE = "csrf_token";
const CSRF_HEADER = "x-csrf-token";
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

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



  const path = req.path || req.url;

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
  // NOTE: This MUST NOT bypass /oidc/login, /oidc/register, or /oidc/mfa,
  // which are standard browser-based web forms that rely on the session cookie
  // and MUST be CSRF-protected.
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
