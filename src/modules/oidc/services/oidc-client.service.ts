import { Injectable } from "@nestjs/common";
import { comparePassword } from "@kannan19302/auth";
import { idpPrisma } from "@kannan19302/database";
import { OAuthError } from "./authorization.service";
import { emitAuthAudit } from "../../../common/audit/emit-auth-audit";
import {
  CLIENT_STATUS,
  CLIENT_TYPE,
  OAUTH_ERROR,
  SCOPE,
} from "../oidc.constants";

/**
 * Client registration lookup and validation.
 *
 * Everything here is about refusing to take the client's word for anything: the
 * redirect target, the scopes, and (for confidential clients) the identity.
 */

export interface OAuthClientRecord {
  clientId: string;
  name: string;
  clientType: string;
  clientSecretHash: string | null;
  platformCode: string | null;
  isFirstParty: boolean;
  ownerTenantId: string | null;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  grantTypes: string[];
  allowedScopes: string[];
  status: string;
}

@Injectable()
export class OidcClientService {
  /**
   * Loads an active client. A suspended or revoked client is treated exactly
   * like one that does not exist — an app whose registration was pulled should
   * not be able to tell the difference.
   */
  async getActiveClient(clientId: string): Promise<OAuthClientRecord> {
    if (!clientId) {
      throw new OAuthError(OAUTH_ERROR.INVALID_CLIENT, "Unknown client");
    }

    const client = await idpPrisma.oAuthClient.findUnique({
      where: { clientId },
    });

    if (!client || client.status !== CLIENT_STATUS.ACTIVE) {
      throw new OAuthError(OAUTH_ERROR.INVALID_CLIENT, "Unknown client");
    }

    return client as OAuthClientRecord;
  }

  /**
   * Redirect URIs are matched **exactly** — full string equality, no prefix
   * matching, no wildcards, no ignoring the query string.
   *
   * This is the single most abused part of OAuth. Prefix matching lets an
   * attacker who can register `https://app.example.com/cb` redeem a code at
   * `https://app.example.com/cb/../../evil`; allowing open redirects on the
   * registered host achieves the same thing. Exact match is the only rule that
   * does not require reasoning about URL parsing quirks.
   */
  validateRedirectUri(client: OAuthClientRecord, redirectUri: string): void {
    if (!redirectUri || !client.redirectUris.includes(redirectUri)) {
      // Deliberately NOT redirected back to the client: if the redirect URI is
      // untrusted, sending an error to it is itself the open redirect. RFC 6749
      // §4.1.2.1 requires this be shown to the user instead.
      throw new OAuthError(
        OAUTH_ERROR.INVALID_REQUEST,
        "redirect_uri does not match a registered redirect URI",
      );
    }
  }

  validatePostLogoutRedirectUri(
    client: OAuthClientRecord,
    redirectUri: string,
  ): void {
    if (!redirectUri || !client.postLogoutRedirectUris.includes(redirectUri)) {
      throw new OAuthError(
        OAUTH_ERROR.INVALID_REQUEST,
        "post_logout_redirect_uri does not match a registered URI",
      );
    }
  }

  /** A client may only use grant types it was registered for. */
  assertGrantAllowed(client: OAuthClientRecord, grantType: string): void {
    if (!client.grantTypes.includes(grantType)) {
      throw new OAuthError(
        OAUTH_ERROR.UNAUTHORIZED_CLIENT,
        `Client is not permitted to use ${grantType}`,
      );
    }
  }

  /**
   * Authenticates a confidential client.
   *
   * Public clients (browser SPAs, the Flutter app, the desktop shell) have no
   * secret to present — shipping one would put it in every install — so they
   * authenticate with PKCE alone. That is why `client_type` exists: a public
   * client is not a confidential client that forgot its secret, and must never
   * be allowed to authenticate as one.
   */
  async authenticateClient(
    client: OAuthClientRecord,
    presentedSecret?: string,
  ): Promise<void> {
    if (client.clientType === CLIENT_TYPE.PUBLIC) {
      // A public client presenting a secret is a misconfiguration at best and
      // an impersonation attempt at worst; either way the secret means nothing.
      return;
    }

    if (!presentedSecret || !client.clientSecretHash) {
      throw new OAuthError(
        OAUTH_ERROR.INVALID_CLIENT,
        "Client authentication failed",
      );
    }

    const ok = await comparePassword(presentedSecret, client.clientSecretHash);
    if (!ok) {
      throw new OAuthError(
        OAUTH_ERROR.INVALID_CLIENT,
        "Client authentication failed",
      );
    }
  }

  /**
   * Narrows the requested scopes to what the client is registered for.
   *
   * Requesting a scope outside the registration is rejected rather than
   * silently dropped: a client that believes it holds `erp.write` and actually
   * does not should fail loudly at authorization time, not mysteriously at the
   * first write.
   *
   * This is only the first of three narrowings. The token's real authority is
   * scopes ∩ user permissions ∩ tenant entitlements.
   */
  resolveScopes(client: OAuthClientRecord, requested: string[]): string[] {
    const wanted = requested.filter(Boolean);

    if (wanted.length === 0) {
      // OIDC requires `openid` for an id_token; default to the minimum rather
      // than granting everything the client is allowed to ask for.
      return [SCOPE.OPENID];
    }

    const disallowed = wanted.filter((s) => !client.allowedScopes.includes(s));
    if (disallowed.length > 0) {
      throw new OAuthError(
        OAUTH_ERROR.INVALID_SCOPE,
        `Scope not permitted for this client: ${disallowed.join(", ")}`,
      );
    }

    // `agent` is never obtainable through a normal authorization request.
    // Delegated agent authority comes only from token exchange against a live
    // user token (W2), so that it is always strictly derived from a human's
    // authority rather than granted directly to an application.
    if (wanted.includes(SCOPE.AGENT)) {
      throw new OAuthError(
        OAUTH_ERROR.INVALID_SCOPE,
        "The agent scope is only available through token exchange",
      );
    }

    return Array.from(new Set(wanted));
  }

  /**
   * First-party platforms are pre-consented — showing a consent screen when a
   * user moves from the tenant admin console to the ERP would be noise, not
   * safety. Third-party apps always require an explicit grant.
   */
  async needsConsent(
    client: OAuthClientRecord,
    userId: string,
    tenantId: string,
    scopes: string[],
  ): Promise<boolean> {
    if (client.isFirstParty) return false;

    const consent = await idpPrisma.clientConsent.findUnique({
      where: {
        clientId_userId_tenantId: {
          clientId: client.clientId,
          userId,
          tenantId,
        },
      },
    });

    if (!consent || consent.revokedAt) return true;

    // A previously granted consent does not cover scopes added since. Asking
    // again for the new ones is the whole point of recording what was granted.
    return scopes.some((s) => !consent.scopes.includes(s));
  }

  async recordConsent(params: {
    clientId: string;
    userId: string;
    tenantId: string;
    scopes: string[];
  }): Promise<void> {
    await idpPrisma.clientConsent.upsert({
      where: {
        clientId_userId_tenantId: {
          clientId: params.clientId,
          userId: params.userId,
          tenantId: params.tenantId,
        },
      },
      create: {
        clientId: params.clientId,
        userId: params.userId,
        tenantId: params.tenantId,
        scopes: params.scopes,
      },
      update: { scopes: params.scopes, revokedAt: null, grantedAt: new Date() },
    });
  }

  async revokeConsent(params: {
    clientId: string;
    userId: string;
    tenantId: string;
  }): Promise<void> {
    await idpPrisma.clientConsent.updateMany({
      where: { ...params, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    await emitAuthAudit({
      tenantId: params.tenantId,
      userId: params.userId,
      action: "AUTH_CONSENT_REVOKE",
      entityType: "OAuthClient",
      entityId: params.clientId,
    });
  }
}
