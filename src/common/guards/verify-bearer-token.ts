import { verifyTypedToken, TOKEN_TYPE } from "@kannan19302/auth";
import { createRemoteJWKSet, jwtVerify } from "jose";

export interface VerifiedClaims {
  sid?: string;
  tenantId?: string;
  userId?: string;
  realm?: "tenant" | "provider";
  roles?: string[];
  permissions?: string[];
  mfaVerified?: boolean;
  [key: string]: unknown;
}

const jwks = createRemoteJWKSet(
  new URL(`${process.env.OIDC_ISSUER ?? "http://localhost:3005"}/oidc/jwks.json`),
);

/**
 * Two token shapes are both legitimate "I am signed in" evidence, and every
 * guard needs to accept either:
 *
 *  - The legacy HS256 session cookie `auth.service.ts` mints directly
 *    (`issueSession`), verified with the shared secret via `verifyTypedToken`.
 *  - The RS256 OIDC access token `OidcTokenService.mintAccessToken` issues
 *    from `/oidc/token`, which every relying party wired in W6 (and mobile,
 *    W11) sends as a Bearer token, verified against idp's own JWKS.
 *
 * `OidcTokenService`'s doc comment says the claim shape is "deliberately
 * compatible" with the legacy guards — true for `sid`/`tenantId`/`roles`/
 * `permissions`/`typ`, but the *subject* is carried differently: the legacy
 * token has a `userId` field, the OIDC token has the standard JWT `sub`
 * claim. Without normalising that here, every OIDC-authenticated request
 * would verify successfully and then fail downstream the moment anything
 * reads `user.userId` (RbacGuard, TenantInterceptor, every controller). This
 * is that normalisation, done once, in the one place both guards can share.
 */
export async function verifyBearerToken(token: string): Promise<VerifiedClaims | null> {
  const legacy = verifyTypedToken<VerifiedClaims>(token, TOKEN_TYPE.SESSION);
  if (legacy) return legacy;

  try {
    const { payload } = await jwtVerify(token, jwks, {
      issuer: process.env.OIDC_ISSUER ?? "http://localhost:3005",
    });
    if (payload.typ !== "session" || !payload.sub) return null;
    return {
      ...payload,
      userId: payload.sub,
    } as VerifiedClaims;
  } catch {
    return null;
  }
}
