import {
  Injectable,
  BadRequestException,
  ForbiddenException,
  NotFoundException,
  UnauthorizedException,
  Logger,
} from "@nestjs/common";
import { createHash, randomBytes } from "node:crypto";
import { SAML } from "@node-saml/node-saml";
import { idpPrisma, prisma, runWithTenantSession } from "@kannan19302/database";
import { createRemoteJWKSet, type JWTPayload } from "jose";
import { AuthService, SessionContext } from "./auth.service";
import { ExternalAuthStore } from "./external-auth.store";
import { assertSsoFederationEnabled } from "./sso-plan-gate";
import { verifyInboundOidcToken } from "./inbound-oidc-verifier";
import {
  decryptConfigurationSecret,
  discoverOidcConfiguration,
  requirePublicHttpsUrl,
  type OidcDiscoveryDocument,
} from "@kannan19302/auth";
import { emitAuthAudit } from "../../common/audit/emit-auth-audit";

interface SsoProfile {
  email: string;
  firstName?: string;
  lastName?: string;
  provider: "SAML" | "OIDC";
}

export class UniErpSaml extends SAML {
  async generateAuthnRequest(): Promise<{ requestXml: string; requestId: string }> {
    const requestXml = await this.generateAuthorizeRequestAsync(this.options.passive ?? false, false);
    const idMatch = requestXml.match(/ID="([^"]+)"/);
    const requestId = idMatch && idMatch[1] ? idMatch[1] : `_req_${randomBytes(16).toString("hex")}`;
    return { requestXml, requestId };
  }

  async buildAuthorizeRedirectUrl(requestXml: string, relayState: string): Promise<string> {
    const operation = "authorize";
    return this._requestToUrlAsync(
      requestXml,
      null,
      operation,
      this._getAdditionalParams(relayState, operation, {}),
    );
  }
}

/**
 * Inbound SSO federation: a TENANT'S OWN external IdP (their Okta, their
 * Entra tenant, ...) authenticates one of their users, and that assertion is
 * exchanged for a UniERP session — the reverse direction from `idp` being an
 * OIDC provider (W1) or from `oauth.service.ts`'s Google/Microsoft sign-in
 * (which authenticates against ONE fixed, first-party-configured provider).
 *
 * Gated to the Enterprise plan (sso-plan-gate.ts) and, since W0, requires
 * real signature/exchange verification — the previous implementation read an
 * unsigned `email` field out of the callback body directly.
 */
@Injectable()
export class SsoService {
  private readonly logger = new Logger(SsoService.name);
  private readonly jwks = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

  constructor(
    private readonly authService: AuthService,
    private readonly externalAuthStore: ExternalAuthStore,
  ) {}

  private get idpPublicUrl(): string {
    return process.env.OIDC_ISSUER ?? "http://localhost:3005";
  }

  private samlCallbackUrl(tenantSlug: string): string {
    return `${this.idpPublicUrl}/api/v1/auth/sso/saml/callback/${tenantSlug}`;
  }

  private oidcCallbackUrl(tenantSlug: string): string {
    return `${this.idpPublicUrl}/api/v1/auth/sso/oidc/callback/${tenantSlug}`;
  }

  // ── Config lookup ─────────────────────────────────────────────────────
  //
  // Reads the SAME `SsoConfig` rows the tenant admin console writes
  // (api/src/modules/saas-portal/services/security.service.ts's
  // getSsoConfigs/saveSsoConfig) — previously this read a disconnected
  // `Setting` blob keyed "sso_config" that nothing ever wrote to, so a
  // tenant that genuinely configured SAML/OIDC from the admin console would
  // still see `{configured: false}` on the login page. Same schema, same
  // database, one client already reads it (`prisma`); this was a wiring gap,
  // not a missing feature.

  private async requireTenant(tenantSlug: string) {
    const tenant = await prisma.tenant.findUnique({ where: { slug: tenantSlug } });
    if (!tenant) throw new NotFoundException("Tenant not found");
    return tenant;
  }

  private async requireConfig(tenantId: string, providerType: "SAML" | "OIDC") {
    const config = await prisma.ssoConfig.findUnique({
      where: { tenantId_providerType: { tenantId, providerType } },
    });
    if (!config || !config.isActive || config.verificationStatus !== "VERIFIED" || !config.lastVerifiedAt) {
      throw new BadRequestException(`${providerType} SSO is not configured for this organization.`);
    }
    return config;
  }

  async getSsoConfigByTenantSlug(tenantSlug: string) {
    const tenant = await prisma.tenant.findUnique({ where: { slug: tenantSlug } });
    if (!tenant) return null;

    const configs = await prisma.ssoConfig.findMany({
      where: {
        tenantId: tenant.id,
        isActive: true,
        verificationStatus: "VERIFIED",
        lastVerifiedAt: { not: null },
      },
    });
    const saml = configs.find((c) => c.providerType === "SAML");
    const oidc = configs.find((c) => c.providerType === "OIDC");
    if (!saml && !oidc) return { configured: false };

    return {
      configured: true,
      samlEntryPoint: saml?.samlEntryPoint || null,
      oidcAuthorizationUrl: oidc?.authorizationUrl || null,
      oidcClientId: oidc?.clientId || null,
    };
  }

  // ── SAML ──────────────────────────────────────────────────────────────

  private buildSamlClient(tenantSlug: string, config: { samlEntryPoint: string | null; samlIssuer: string | null; samlCert: string | null }): UniErpSaml {
    if (!config.samlEntryPoint || !config.samlCert) {
      throw new BadRequestException("SAML configuration is incomplete for this organization.");
    }
    const spEntityId = config.samlIssuer || `unierp-${tenantSlug}`;
    return new UniErpSaml({
      entryPoint: config.samlEntryPoint,
      issuer: spEntityId,
      callbackUrl: this.samlCallbackUrl(tenantSlug),
      idpCert: config.samlCert,
      wantAssertionsSigned: true,
      wantAuthnResponseSigned: false,
      audience: spEntityId,
      acceptedClockSkewMs: 30_000,
    });
  }

  async buildSamlLoginUrl(tenantSlug: string, returnTo?: string): Promise<string> {
    const tenant = await this.requireTenant(tenantSlug);
    await assertSsoFederationEnabled(tenant.id);
    const config = await this.requireConfig(tenant.id, "SAML");
    const saml = this.buildSamlClient(tenantSlug, config);

    // Generate request XML to extract request ID for assertion correlation
    const { requestXml, requestId } = await saml.generateAuthnRequest();

    // Create opaque server-side RelayState transaction binding
    const relayState = await this.externalAuthStore.createSamlFederationTransaction({
      tenantSlug,
      returnTo: returnTo || "/",
      requestId,
      issuedAt: Date.now(),
    });

    return saml.buildAuthorizeRedirectUrl(requestXml, relayState);
  }

  /**
   * Verifies the POSTed assertion's signature, replay, recipient, destination,
   * audience, time-window, and assertion-correlation against the tenant's stored
   * configuration and server-side state transaction.
   */
  async handleSamlCallback(
    tenantSlug: string,
    body: Record<string, string>,
    context?: SessionContext,
  ) {
    const relayState = String(body?.RelayState || "");
    const transaction = await this.externalAuthStore.consumeSamlFederationTransaction(relayState);
    if (!transaction || transaction.tenantSlug !== tenantSlug) {
      throw new UnauthorizedException("Invalid or expired sign-in state.");
    }

    const tenant = await this.requireTenant(tenantSlug);
    await assertSsoFederationEnabled(tenant.id);
    const config = await this.requireConfig(tenant.id, "SAML");
    const saml = this.buildSamlClient(tenantSlug, config);

    if (!body?.SAMLResponse) {
      throw new UnauthorizedException("The identity provider did not return an assertion.");
    }

    // Inspect assertion XML for destination, recipient, audience, correlation and replay checks
    const rawXml = Buffer.from(body.SAMLResponse, "base64").toString("utf8");

    // 1. InResponseTo assertion correlation check
    const inResponseToMatch = rawXml.match(/InResponseTo="([^"]+)"/);
    if (inResponseToMatch && inResponseToMatch[1] !== transaction.requestId) {
      this.logger.warn(`[sso] SAML InResponseTo mismatch for ${tenantSlug}: expected ${transaction.requestId}, received ${inResponseToMatch[1]}`);
      throw new UnauthorizedException("SAML assertion response correlation mismatch.");
    }

    // 2. Destination / Recipient check
    const expectedAcs = this.samlCallbackUrl(tenantSlug);
    const destinationMatch = rawXml.match(/Destination="([^"]+)"/);
    if (destinationMatch && destinationMatch[1] !== expectedAcs) {
      this.logger.warn(`[sso] SAML Destination mismatch for ${tenantSlug}: expected ${expectedAcs}, received ${destinationMatch[1]}`);
      throw new UnauthorizedException("SAML assertion destination mismatch.");
    }
    const recipientMatch = rawXml.match(/Recipient="([^"]+)"/);
    if (recipientMatch && recipientMatch[1] !== expectedAcs) {
      this.logger.warn(`[sso] SAML Recipient mismatch for ${tenantSlug}: expected ${expectedAcs}, received ${recipientMatch[1]}`);
      throw new UnauthorizedException("SAML assertion recipient mismatch.");
    }

    // 3. Audience check
    const audienceMatch = rawXml.match(/<saml(?:2)?:Audience>([^<]+)<\/saml(?:2)?:Audience>/);
    const expectedAudience = config.samlIssuer || `unierp-${tenantSlug}`;
    if (audienceMatch && audienceMatch[1] !== expectedAudience) {
      this.logger.warn(`[sso] SAML Audience mismatch for ${tenantSlug}: expected ${expectedAudience}, received ${audienceMatch[1]}`);
      throw new UnauthorizedException("SAML assertion audience mismatch.");
    }

    // 4. Assertion ID replay defense
    const assertionIdMatch = rawXml.match(/<saml(?:2)?:Assertion[^>]*\sID="([^"]+)"/);
    if (assertionIdMatch && assertionIdMatch[1]) {
      const assertionId = assertionIdMatch[1];
      const fresh = await this.externalAuthStore.recordSamlAssertion(assertionId);
      if (!fresh) {
        this.logger.warn(`[sso] Replayed SAML assertion ${assertionId} rejected for ${tenantSlug}`);
        throw new UnauthorizedException("Replayed SAML assertion rejected.");
      }
    }

    let profile;
    try {
      const result = await saml.validatePostResponseAsync(body);
      profile = result.profile;
    } catch (error) {
      this.logger.warn(
        `[sso] SAML assertion rejected for tenant ${tenantSlug}: ${error instanceof Error ? error.message : error}`,
      );
      throw new UnauthorizedException("Your identity provider's response could not be verified.");
    }
    if (!profile) {
      throw new UnauthorizedException("The identity provider did not return an assertion.");
    }

    const email = String(profile.email || profile.mail || (profile.nameIDFormat?.includes("emailAddress") ? profile.nameID : "")).toLowerCase();
    if (!email || !email.includes("@")) {
      throw new UnauthorizedException("Your identity provider did not supply an email address.");
    }

    const user = await this.resolveOrCreateUser(tenant.id, {
      email,
      firstName: (profile.firstName as string) || (profile.givenName as string) || undefined,
      lastName: (profile.lastName as string) || (profile.sn as string) || undefined,
      provider: "SAML",
    });

    await emitAuthAudit({
      tenantId: tenant.id,
      userId: user.id,
      action: "SSO_FEDERATION_LOGIN_SUCCESS",
      entityType: "SsoConfig",
      entityId: config.id,
      changes: { provider: "SAML", email: user.email },
      ipAddress: context?.ipAddress ?? undefined,
    });

    return {
      session: await this.authService.issueSession(user, context, { realm: "tenant" }),
      returnTo: transaction.returnTo || undefined,
    };
  }

  // ── OIDC ──────────────────────────────────────────────────────────────
  //
  // The browser receives only an opaque, one-time state handle. Endpoint
  // trust is obtained from the configured issuer's discovery document, not
  // from arbitrary tenant-entered callback URLs.

  async buildOidcLoginUrl(tenantSlug: string, returnTo: string): Promise<string> {
    const tenant = await this.requireTenant(tenantSlug);
    await assertSsoFederationEnabled(tenant.id);
    const config = await this.requireConfig(tenant.id, "OIDC");
    if (!config.clientId) {
      throw new BadRequestException("OIDC configuration is incomplete for this organization.");
    }
    const discovered = await this.discoverOidcConfiguration(config);
    const nonce = randomBytes(24).toString("base64url");
    const codeVerifier = randomBytes(48).toString("base64url");
    const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");
    const state = await this.externalAuthStore.createFederationTransaction({
      tenantSlug,
      returnTo,
      nonce,
      codeVerifier,
    });

    const params = new URLSearchParams({
      client_id: config.clientId,
      redirect_uri: this.oidcCallbackUrl(tenantSlug),
      response_type: "code",
      scope: "openid email profile",
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    });
    return `${discovered.authorization_endpoint}?${params.toString()}`;
  }

  async handleOidcCallback(
    tenantSlug: string,
    code: string,
    state: string,
    context?: SessionContext,
  ) {
    const transaction = await this.externalAuthStore.consumeFederationTransaction(state);
    if (!transaction || transaction.tenantSlug !== tenantSlug) {
      throw new UnauthorizedException("Invalid or expired sign-in state.");
    }

    const tenant = await this.requireTenant(tenantSlug);
    await assertSsoFederationEnabled(tenant.id);
    const config = await this.requireConfig(tenant.id, "OIDC");
    if (!config.clientId || !code || code.length > 4096) {
      throw new BadRequestException("OIDC configuration is incomplete for this organization.");
    }
    const discovered = await this.discoverOidcConfiguration(config);

    const tokenRes = await fetch(discovered.token_endpoint, {
      method: "POST",
      redirect: "error",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: config.clientId,
        ...(config.clientSecret ? { client_secret: this.decryptClientSecret(config.clientSecret) } : {}),
        code,
        code_verifier: transaction.codeVerifier,
        grant_type: "authorization_code",
        redirect_uri: this.oidcCallbackUrl(tenantSlug),
      }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!tokenRes.ok) {
      this.logger.warn(`[sso] OIDC code exchange failed for tenant ${tenantSlug}: ${tokenRes.status}`);
      throw new UnauthorizedException("Sign-in could not be completed.");
    }
    const tokens = (await tokenRes.json()) as { id_token?: string };
    if (!tokens.id_token) {
      throw new UnauthorizedException("Identity provider returned no identity token.");
    }

    const claims = await this.verifyOidcToken(
      tokens.id_token,
      config.clientId,
      transaction.nonce,
      discovered,
    );

    const email = String(claims.email ?? "").toLowerCase();
    if (!email || !email.includes("@") || claims.email_verified !== true) {
      throw new UnauthorizedException("Your identity provider did not supply a verified email address.");
    }

    const name = String(claims.name ?? "");
    const user = await this.resolveOrCreateUser(tenant.id, {
      email,
      firstName: (claims.given_name as string) || name.split(" ")[0] || undefined,
      lastName: (claims.family_name as string) || name.split(" ").slice(1).join(" ") || undefined,
      provider: "OIDC",
    });

    await emitAuthAudit({
      tenantId: tenant.id,
      userId: user.id,
      action: "SSO_FEDERATION_LOGIN_SUCCESS",
      entityType: "SsoConfig",
      entityId: config.id,
      changes: { provider: "OIDC", email: user.email },
      ipAddress: context?.ipAddress ?? undefined,
    });

    return {
      session: await this.authService.issueSession(user, context, { realm: "tenant" }),
      returnTo: transaction.returnTo,
    };
  }

  private async discoverOidcConfiguration(config: {
    issuerUrl: string | null;
  }): Promise<OidcDiscoveryDocument> {
    try {
      requirePublicHttpsUrl(config.issuerUrl, "OIDC issuer");
    } catch (error) {
      throw new BadRequestException(error instanceof Error ? error.message : "OIDC issuer is invalid.");
    }
    try {
      return await discoverOidcConfiguration(config.issuerUrl);
    } catch (error) {
      this.logger.warn(`[sso] OIDC discovery rejected: ${error instanceof Error ? error.message : "invalid metadata"}`);
      throw new UnauthorizedException("Identity provider metadata is unavailable or invalid.");
    }
  }

  private async verifyOidcToken(
    idToken: string,
    clientId: string,
    nonce: string,
    discovery: OidcDiscoveryDocument,
  ): Promise<JWTPayload> {
    const algorithms = discovery.id_token_signing_alg_values_supported;
    try {
      return await verifyInboundOidcToken(idToken, this.keySetFor(discovery.jwks_uri), {
        issuer: discovery.issuer,
        clientId,
        nonce,
        algorithms,
        maxTokenAge: "5m",
        clockToleranceSeconds: 30,
      });
    } catch (error) {
      this.logger.warn(`[sso] OIDC ID token verification failed: ${error instanceof Error ? error.message : "unknown verification error"}`);
      throw new UnauthorizedException("Identity response could not be verified.");
    }
  }

  private keySetFor(jwksUrl: string) {
    const cached = this.jwks.get(jwksUrl);
    if (cached) return cached;
    const keySet = createRemoteJWKSet(new URL(jwksUrl), {
      timeoutDuration: 5_000,
      cooldownDuration: 30_000,
      cacheMaxAge: 10 * 60_000,
    });
    this.jwks.set(jwksUrl, keySet);
    return keySet;
  }

  private decryptClientSecret(envelope: string): string {
    try {
      return decryptConfigurationSecret(envelope);
    } catch {
      throw new UnauthorizedException("Federation client credentials are unavailable.");
    }
  }

  // ── Shared JIT provisioning ──────────────────────────────────────────

  private async resolveOrCreateUser(tenantId: string, profile: SsoProfile) {
    // The callback is unauthenticated, so no tenant session exists yet; run
    // provisioning inside an explicit tenant session so RLS on users/roles
    // accepts it (#21 Track C) — same reasoning as the pre-federation code.
    const user = await runWithTenantSession(
      { tenantId, userId: "sso-jit" },
      async () => {
        let existing = await idpPrisma.user.findFirst({
          where: { tenantId, email: profile.email },
        });

        if (!existing) {
          existing = await idpPrisma.user.create({
            data: {
              tenantId,
              email: profile.email,
              firstName: profile.firstName || profile.email.split("@")[0] || "SSO",
              lastName: profile.lastName || "User",
              status: "ACTIVE",
              passwordHash: null,
            },
          });

          const viewerRole = await idpPrisma.role.findFirst({
            where: { tenantId, name: "Viewer" },
          });
          if (viewerRole) {
            await idpPrisma.userRole.create({
              data: { userId: existing.id, roleId: viewerRole.id },
            });
          }

          await emitAuthAudit({
            tenantId,
            userId: existing.id,
            action: "SSO_USER_PROVISIONED",
            entityType: "User",
            entityId: existing.id,
            changes: { email: profile.email, provider: profile.provider },
          });
        }
        return existing;
      },
    );

    if (user.status !== "ACTIVE") {
      throw new ForbiddenException(`Account is ${user.status?.toLowerCase()}`);
    }
    // `AuthService.issueSession` lazily resolves `user.tenant` itself when
    // absent — no need to preload it here.
    return user;
  }
}
