import {
  Injectable,
  BadRequestException,
  ForbiddenException,
  NotFoundException,
  UnauthorizedException,
  Logger,
} from "@nestjs/common";
import { SAML } from "@node-saml/node-saml";
import { idpPrisma, prisma, runWithTenantSession } from "@kannan19302/database";
import { signTypedToken, verifyTypedToken, TOKEN_TYPE } from "@kannan19302/auth";
import { AuthService, SessionContext } from "./auth.service";
import { assertSsoFederationEnabled } from "./sso-plan-gate";

interface SsoProfile {
  email: string;
  firstName?: string;
  lastName?: string;
  provider: "SAML" | "OIDC";
}

/** How long the signed OIDC federation `state` stays valid. */
const OIDC_STATE_TTL = "10m";

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

  constructor(private readonly authService: AuthService) {}

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
    if (!config || !config.isActive) {
      throw new BadRequestException(`${providerType} SSO is not configured for this organization.`);
    }
    return config;
  }

  async getSsoConfigByTenantSlug(tenantSlug: string) {
    const tenant = await prisma.tenant.findUnique({ where: { slug: tenantSlug } });
    if (!tenant) return null;

    const configs = await prisma.ssoConfig.findMany({
      where: { tenantId: tenant.id, isActive: true },
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

  private buildSamlClient(tenantSlug: string, config: { samlEntryPoint: string | null; samlIssuer: string | null; samlCert: string | null }): SAML {
    if (!config.samlEntryPoint || !config.samlCert) {
      throw new BadRequestException("SAML configuration is incomplete for this organization.");
    }
    return new SAML({
      entryPoint: config.samlEntryPoint,
      issuer: config.samlIssuer || `unierp-${tenantSlug}`,
      callbackUrl: this.samlCallbackUrl(tenantSlug),
      idpCert: config.samlCert,
      wantAssertionsSigned: true,
      wantAuthnResponseSigned: false,
    });
  }

  async buildSamlLoginUrl(tenantSlug: string, returnTo: string): Promise<string> {
    const tenant = await this.requireTenant(tenantSlug);
    await assertSsoFederationEnabled(tenant.id);
    const config = await this.requireConfig(tenant.id, "SAML");
    const saml = this.buildSamlClient(tenantSlug, config);
    // RelayState round-trips through the IdP unmodified — it's what carries
    // `returnTo` back to us, since the IdP has no notion of it otherwise.
    return saml.getAuthorizeUrlAsync(returnTo, undefined, {});
  }

  /**
   * Verifies the POSTed assertion's signature against the tenant's stored
   * `samlCert` — the fix for the disabled controller's original hole. A
   * forged or unsigned assertion fails `validatePostResponseAsync` and
   * throws before any session is minted.
   */
  async handleSamlCallback(
    tenantSlug: string,
    body: Record<string, string>,
    context?: SessionContext,
  ) {
    const tenant = await this.requireTenant(tenantSlug);
    await assertSsoFederationEnabled(tenant.id);
    const config = await this.requireConfig(tenant.id, "SAML");
    const saml = this.buildSamlClient(tenantSlug, config);

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

    return {
      session: await this.authService.issueSession(user, context, { realm: "tenant" }),
      returnTo: (body.RelayState as string) || undefined,
    };
  }

  // ── OIDC ──────────────────────────────────────────────────────────────
  //
  // Deliberately mirrors oauth.service.ts's Google/Microsoft flow rather
  // than adding an OIDC client library: the code exchange happens over a
  // direct server-to-server HTTPS request to the tenant's OWN configured
  // token endpoint, which is the same trust boundary oauth.service.ts
  // already relies on to skip a separate id_token signature check — the
  // token arrives straight from the issuer over TLS, with no third party in
  // that hop, unlike a SAML assertion which transits the user's browser.

  async buildOidcLoginUrl(tenantSlug: string, returnTo: string): Promise<string> {
    const tenant = await this.requireTenant(tenantSlug);
    await assertSsoFederationEnabled(tenant.id);
    const config = await this.requireConfig(tenant.id, "OIDC");
    if (!config.authorizationUrl || !config.clientId) {
      throw new BadRequestException("OIDC configuration is incomplete for this organization.");
    }

    const state = signTypedToken(
      TOKEN_TYPE.OAUTH_STATE,
      { tenantSlug, returnTo },
      OIDC_STATE_TTL,
    );

    const params = new URLSearchParams({
      client_id: config.clientId,
      redirect_uri: this.oidcCallbackUrl(tenantSlug),
      response_type: "code",
      scope: "openid email profile",
      state,
    });
    return `${config.authorizationUrl}?${params.toString()}`;
  }

  async handleOidcCallback(
    tenantSlug: string,
    code: string,
    state: string,
    context?: SessionContext,
  ) {
    const decoded = verifyTypedToken<{ tenantSlug: string; returnTo?: string }>(
      state,
      TOKEN_TYPE.OAUTH_STATE,
    );
    if (!decoded || decoded.tenantSlug !== tenantSlug) {
      throw new UnauthorizedException("Invalid or expired sign-in state.");
    }

    const tenant = await this.requireTenant(tenantSlug);
    await assertSsoFederationEnabled(tenant.id);
    const config = await this.requireConfig(tenant.id, "OIDC");
    if (!config.tokenUrl || !config.clientId) {
      throw new BadRequestException("OIDC configuration is incomplete for this organization.");
    }

    const tokenRes = await fetch(config.tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: config.clientId,
        ...(config.clientSecret ? { client_secret: config.clientSecret } : {}),
        code,
        grant_type: "authorization_code",
        redirect_uri: this.oidcCallbackUrl(tenantSlug),
      }),
    });
    if (!tokenRes.ok) {
      this.logger.warn(
        `[sso] OIDC code exchange failed for tenant ${tenantSlug}: ${tokenRes.status} ${await tokenRes.text().catch(() => "")}`,
      );
      throw new UnauthorizedException("Sign-in could not be completed.");
    }
    const tokens = (await tokenRes.json()) as { id_token?: string };
    if (!tokens.id_token) {
      throw new UnauthorizedException("Identity provider returned no identity token.");
    }

    const claims = JSON.parse(
      Buffer.from(tokens.id_token.split(".")[1] ?? "", "base64url").toString("utf8"),
    ) as Record<string, unknown>;

    const email = String(claims.email ?? claims.preferred_username ?? "").toLowerCase();
    if (!email || !email.includes("@")) {
      throw new UnauthorizedException("Your identity provider did not supply an email address.");
    }

    const name = String(claims.name ?? "");
    const user = await this.resolveOrCreateUser(tenant.id, {
      email,
      firstName: (claims.given_name as string) || name.split(" ")[0] || undefined,
      lastName: (claims.family_name as string) || name.split(" ").slice(1).join(" ") || undefined,
      provider: "OIDC",
    });

    return {
      session: await this.authService.issueSession(user, context, { realm: "tenant" }),
      returnTo: decoded.returnTo,
    };
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
