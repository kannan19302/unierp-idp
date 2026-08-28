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
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import { AuthService, SessionContext } from "./auth.service";
import { ExternalAuthStore } from "./external-auth.store";
import { assertSsoFederationEnabled } from "./sso-plan-gate";

interface SsoProfile {
  email: string;
  firstName?: string;
  lastName?: string;
  provider: "SAML" | "OIDC";
}

const OIDC_ALLOWED_SIGNING_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"];

interface OidcDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  id_token_signing_alg_values_supported?: string[];
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
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: config.clientId,
        ...(config.clientSecret ? { client_secret: config.clientSecret } : {}),
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

    return {
      session: await this.authService.issueSession(user, context, { realm: "tenant" }),
      returnTo: transaction.returnTo,
    };
  }

  private async discoverOidcConfiguration(config: {
    issuerUrl: string | null;
  }): Promise<OidcDiscoveryDocument> {
    const issuer = requirePublicHttpsUrl(config.issuerUrl, "OIDC issuer");
    const discoveryUrl = new URL(`${normalizeIssuer(issuer)}/.well-known/openid-configuration`);
    let response: Response;
    try {
      response = await fetch(discoveryUrl, { signal: AbortSignal.timeout(10_000) });
    } catch {
      throw new UnauthorizedException("Identity provider metadata is unavailable.");
    }
    if (!response.ok) {
      this.logger.warn(`[sso] OIDC discovery failed for issuer ${issuer.origin}: ${response.status}`);
      throw new UnauthorizedException("Identity provider metadata is unavailable.");
    }

    let metadata: OidcDiscoveryDocument;
    try {
      metadata = await response.json() as OidcDiscoveryDocument;
    } catch {
      throw new UnauthorizedException("Identity provider metadata is invalid.");
    }
    if (metadata.issuer !== normalizeIssuer(issuer)) {
      throw new UnauthorizedException("Identity provider issuer does not match the configured issuer.");
    }
    for (const [label, endpoint] of Object.entries({
      authorization: metadata.authorization_endpoint,
      token: metadata.token_endpoint,
      JWKS: metadata.jwks_uri,
    })) {
      // OIDC discovery is authoritative for endpoint placement. Some valid
      // issuers (for example hosted providers) publish JWKS on a separate
      // origin, so same-origin enforcement would break conformant providers.
      // Each discovered endpoint is still syntactically constrained here and
      // production egress policy supplies the network-level SSRF boundary.
      requirePublicHttpsUrl(endpoint, `OIDC ${label} endpoint`);
    }
    return metadata;
  }

  private async verifyOidcToken(
    idToken: string,
    clientId: string,
    nonce: string,
    discovery: OidcDiscoveryDocument,
  ): Promise<JWTPayload> {
    const algorithms = discovery.id_token_signing_alg_values_supported
      ?.filter((algorithm) => OIDC_ALLOWED_SIGNING_ALGORITHMS.includes(algorithm)) ?? [];
    if (algorithms.length === 0) {
      throw new UnauthorizedException("Identity provider does not advertise a supported signing algorithm.");
    }
    try {
      const verified = await jwtVerify(idToken, this.keySetFor(discovery.jwks_uri), {
        algorithms,
        issuer: discovery.issuer,
        audience: clientId,
        maxTokenAge: "5m",
        clockTolerance: 30,
      });
      const audience = verified.payload.aud;
      if (Array.isArray(audience) && verified.payload.azp !== clientId) {
        throw new UnauthorizedException("Identity response authorized party is invalid.");
      }
      if (verified.payload.nonce !== nonce) {
        throw new UnauthorizedException("Identity response nonce is invalid.");
      }
      return verified.payload;
    } catch (error) {
      if (error instanceof UnauthorizedException) throw error;
      this.logger.warn(`[sso] OIDC ID token verification failed: ${error instanceof Error ? error.message : "unknown verification error"}`);
      throw new UnauthorizedException("Identity response could not be verified.");
    }
  }

  private keySetFor(jwksUrl: string) {
    const cached = this.jwks.get(jwksUrl);
    if (cached) return cached;
    const keySet = createRemoteJWKSet(requirePublicHttpsUrl(jwksUrl, "OIDC JWKS endpoint"), {
      timeoutDuration: 5_000,
      cooldownDuration: 30_000,
      cacheMaxAge: 10 * 60_000,
    });
    this.jwks.set(jwksUrl, keySet);
    return keySet;
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

function requirePublicHttpsUrl(value: string | null | undefined, label: string): URL {
  if (!value || value.length > 2048) {
    throw new BadRequestException(`${label} is required and must be a valid HTTPS URL.`);
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new BadRequestException(`${label} must be a valid HTTPS URL.`);
  }
  const host = url.hostname.toLowerCase();
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    host === "localhost" ||
    host.endsWith(".localhost") ||
    isPrivateIpAddress(host)
  ) {
    throw new BadRequestException(`${label} must be a public HTTPS URL.`);
  }
  return url;
}

function normalizeIssuer(url: URL): string {
  return url.toString().replace(/\/$/, "");
}

function isPrivateIpAddress(host: string): boolean {
  if (/^127\./.test(host) || /^10\./.test(host) || /^0\./.test(host)) return true;
  if (/^192\.168\./.test(host) || /^169\.254\./.test(host)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return true;
  return host === "::1" || host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80:");
}
