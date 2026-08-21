import { Injectable, Logger } from "@nestjs/common";
import { createHash, randomBytes } from "node:crypto";
import { SignJWT } from "jose";
import { idpPrisma, runWithTenantSession } from "@kannan19302/database";
import { SigningKeyService } from "./signing-key.service";
import { OAuthError } from "./authorization.service";
import { OAUTH_ERROR, SCOPE, TOKEN_TTL } from "../oidc.constants";

/**
 * Mints and rotates tokens.
 *
 * Claim shape is deliberately compatible with what the existing guards already
 * read (`sub`, `tenantId`, `realm`, `roles`, `permissions`, `sid`, `mfaVerified`,
 * `amr`, `typ`), so RbacGuard, ControlPlaneGuard and JwtAuthGuard keep working
 * unchanged while the signing algorithm moves from a shared HS256 secret to
 * RS256 held only here. Three claims are added:
 *
 *   `plat`  the platform the token was issued for, so a token minted for the
 *           marketplace cannot be replayed against the provider console;
 *   `aud`   the client it was issued to;
 *   `scope` the consented scopes, which bound authority further.
 */

export interface AccessTokenClaims {
  sub: string;
  sid: string;
  tenantId: string;
  realm: "tenant" | "provider";
  roles: string[];
  permissions: string[];
  scopes: string[];
  clientId: string;
  platformCode?: string | null;
  mfaVerified?: boolean;
  amr?: string[];
  /** Present only on delegated agent tokens (W2). */
  act?: { agentId: string };
}

export interface IssuedTokens {
  accessToken: string;
  idToken?: string;
  refreshToken?: string;
  expiresIn: number;
  scope: string;
  tokenType: "Bearer";
}

@Injectable()
export class OidcTokenService {
  private readonly logger = new Logger(OidcTokenService.name);

  constructor(private readonly keys: SigningKeyService) {}

  private get issuer(): string {
    // Must match the `issuer` in the discovery document exactly — relying
    // parties compare them verbatim.
    return process.env.OIDC_ISSUER ?? "http://localhost:3005";
  }

  async mintAccessToken(claims: AccessTokenClaims): Promise<string> {
    const key = await this.keys.getCurrentKey();
    const now = Math.floor(Date.now() / 1000);

    const jwt = new SignJWT({
      tenantId: claims.tenantId,
      realm: claims.realm,
      roles: claims.roles,
      permissions: claims.permissions,
      sid: claims.sid,
      scope: claims.scopes.join(" "),
      plat: claims.platformCode ?? null,
      mfaVerified: claims.mfaVerified ?? false,
      amr: claims.amr ?? [],
      // Purpose-scoped, matching TOKEN_TYPE.SESSION in @kannan19302/auth so a
      // reset or MFA-challenge token can never be replayed as a session.
      typ: "session",
      ...(claims.act ? { act: claims.act } : {}),
    })
      .setProtectedHeader({ alg: "RS256", kid: key.kid, typ: "JWT" })
      .setIssuer(this.issuer)
      .setAudience(claims.clientId)
      .setSubject(claims.sub)
      .setIssuedAt(now)
      .setExpirationTime(now + TOKEN_TTL.ACCESS_TOKEN_MS / 1000)
      .setJti(randomBytes(16).toString("base64url"));

    return jwt.sign(key.privateKey);
  }

  /**
   * The id_token is about *authentication* — who signed in — and is consumed by
   * the relying party, never sent to an API. `nonce` is echoed back so the
   * client can bind the response to its own request and reject one it did not
   * initiate.
   */
  async mintIdToken(params: {
    sub: string;
    clientId: string;
    sid: string;
    tenantId: string;
    email?: string;
    name?: string;
    nonce?: string | null;
    scopes: string[];
    authTime?: number;
    amr?: string[];
  }): Promise<string> {
    const key = await this.keys.getCurrentKey();
    const now = Math.floor(Date.now() / 1000);

    const claims: Record<string, unknown> = {
      sid: params.sid,
      auth_time: params.authTime ?? now,
      amr: params.amr ?? [],
    };
    // Only release identity claims the client was actually granted.
    if (params.scopes.includes(SCOPE.EMAIL) && params.email) {
      claims.email = params.email;
    }
    if (params.scopes.includes(SCOPE.PROFILE) && params.name) {
      claims.name = params.name;
    }
    if (params.scopes.includes(SCOPE.TENANT)) {
      claims.tenantId = params.tenantId;
    }
    if (params.nonce) claims.nonce = params.nonce;

    return new SignJWT(claims)
      .setProtectedHeader({ alg: "RS256", kid: key.kid, typ: "JWT" })
      .setIssuer(this.issuer)
      .setAudience(params.clientId)
      .setSubject(params.sub)
      .setIssuedAt(now)
      .setExpirationTime(now + TOKEN_TTL.ID_TOKEN_MS / 1000)
      .sign(key.privateKey);
  }

  /**
   * Issues a refresh token. Stored hashed — this is the long-lived credential,
   * so a database dump must not yield usable ones.
   */
  async issueRefreshToken(params: {
    clientId: string;
    userId: string;
    tenantId: string;
    sid: string;
    scopes: string[];
    rotatedFromId?: string;
  }): Promise<string> {
    const token = randomBytes(32).toString("base64url");

    await idpPrisma.refreshGrant.create({
      data: {
        tokenHash: hashToken(token),
        clientId: params.clientId,
        userId: params.userId,
        tenantId: params.tenantId,
        sid: params.sid,
        scopes: params.scopes,
        expiresAt: new Date(Date.now() + TOKEN_TTL.REFRESH_TOKEN_MS),
        rotatedFromId: params.rotatedFromId ?? null,
      },
    });

    return token;
  }

  /**
   * Redeems and rotates a refresh token.
   *
   * Rotation is what makes theft detectable. Each token is single-use; the
   * response carries a fresh one. If an already-rotated token is presented
   * again, two parties hold the same credential — the legitimate client and
   * someone who copied it — and there is no way to tell which is which. The
   * only safe response is to revoke the entire chain and force a fresh login.
   */
  async rotateRefreshToken(params: {
    refreshToken: string;
    clientId: string;
  }): Promise<{
    grant: {
      userId: string;
      tenantId: string;
      sid: string;
      scopes: string[];
    };
    newRefreshToken: string;
  }> {
    const tokenHash = hashToken(params.refreshToken);
    const record = await idpPrisma.refreshGrant.findUnique({
      where: { tokenHash },
    });

    if (!record || record.clientId !== params.clientId) {
      throw new OAuthError(OAUTH_ERROR.INVALID_GRANT, "Invalid refresh token");
    }

    if (record.revokedAt) {
      // Reuse of a revoked/rotated token. Tear down the whole session.
      this.logger.warn(
        `Refresh token reuse detected for user ${record.userId}; revoking session ${record.sid}`,
      );
      await idpPrisma.refreshGrant.updateMany({
        where: { sid: record.sid, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      await runWithTenantSession(
        { tenantId: record.tenantId, userId: record.userId },
        () =>
          idpPrisma.userSession.updateMany({
            where: { id: record.sid },
            data: { isActive: false },
          }),
      );
      throw new OAuthError(OAUTH_ERROR.INVALID_GRANT, "Invalid refresh token");
    }

    if (record.expiresAt < new Date()) {
      throw new OAuthError(OAUTH_ERROR.INVALID_GRANT, "Invalid refresh token");
    }

    // The session backing this grant must still be live — otherwise logging
    // out would not actually end anything a refresh token could revive.
    //
    // Read inside a tenant session. user_sessions carries RLS with ENABLE +
    // FORCE and the runtime role is NOBYPASSRLS, so querying it without tenant
    // context returns zero rows — not "revoked", simply invisible — and every
    // refresh fails with invalid_grant while the row sits there active. This is
    // the same trap documented at length in api/src/common/guards/jwt-auth.guard.ts.
    // The tenantId comes from the grant row we just loaded by token hash, so it
    // is server-side state rather than anything the caller supplied.
    const session = await runWithTenantSession(
      { tenantId: record.tenantId, userId: record.userId },
      () =>
        idpPrisma.userSession.findUnique({
          where: { id: record.sid },
          select: { isActive: true, expiresAt: true },
        }),
    );
    if (
      !session ||
      !session.isActive ||
      (session.expiresAt && session.expiresAt < new Date())
    ) {
      throw new OAuthError(OAUTH_ERROR.INVALID_GRANT, "Invalid refresh token");
    }

    // Consume conditionally so two concurrent refreshes cannot both succeed.
    const consumed = await idpPrisma.refreshGrant.updateMany({
      where: { tokenHash, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    if (consumed.count !== 1) {
      throw new OAuthError(OAUTH_ERROR.INVALID_GRANT, "Invalid refresh token");
    }

    const newRefreshToken = await this.issueRefreshToken({
      clientId: record.clientId,
      userId: record.userId,
      tenantId: record.tenantId,
      sid: record.sid,
      scopes: record.scopes,
      rotatedFromId: record.id,
    });

    return {
      grant: {
        userId: record.userId,
        tenantId: record.tenantId,
        sid: record.sid,
        scopes: record.scopes,
      },
      newRefreshToken,
    };
  }

  /** Revokes a single refresh token (RFC 7009). Unknown tokens succeed silently. */
  async revokeRefreshToken(refreshToken: string): Promise<void> {
    await idpPrisma.refreshGrant.updateMany({
      where: { tokenHash: hashToken(refreshToken), revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }
}

/** Refresh tokens are stored hashed, never in clear text. */
export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("base64url");
}
