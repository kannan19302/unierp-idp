import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
  Logger,
} from "@nestjs/common";
import { createHash, randomBytes } from "node:crypto";
import {
  createRemoteJWKSet,
  decodeJwt,
  jwtVerify,
  type JWTPayload,
} from "jose";
import { idpPrisma, prisma, runWithTenantSession } from "@kannan19302/database";
import { AuthService, SessionContext } from "./auth.service";
import { PlatformCredentialsService } from "../../common/platform-credentials/platform-credentials.service";
import {
  ExternalAuthStore,
  type ExternalAuthJourney,
  type ExternalAuthProvider,
  type ExternalRegistrationProfile,
} from "./external-auth.store";
import { emitAuthAudit } from "../../common/audit/emit-auth-audit";

export type OAuthProviderName = ExternalAuthProvider;

interface ProviderConfig {
  authorizeUrl: string;
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  scope: string;
  issuer?: string;
  jwksUrl?: string;
  microsoftTenant?: string;
}

interface OAuthProfile {
  subject: string;
  email: string;
  emailVerified: boolean;
  firstName?: string;
  lastName?: string;
}

export type OAuthCallbackResult =
  | ({ kind: "session"; returnTo: string } & Record<string, unknown>)
  | { kind: "registration"; registrationTicket: string; returnTo: string };

const VISIBLE_PROVIDERS = ["google", "microsoft", "github"] as const;

/** Live upstream authentication for the single hosted UniERP auth portal. */
@Injectable()
export class OAuthService {
  private readonly logger = new Logger(OAuthService.name);
  private readonly jwks = new Map<
    string,
    ReturnType<typeof createRemoteJWKSet>
  >();

  constructor(
    private readonly authService: AuthService,
    private readonly platformCredentialsService: PlatformCredentialsService,
    private readonly externalAuthStore: ExternalAuthStore,
  ) {}

  private get apiUrl(): string {
    return process.env.API_PUBLIC_URL || "http://localhost:3001";
  }

  private redirectUri(provider: OAuthProviderName): string {
    return `${this.apiUrl}/api/v1/auth/oauth/${provider}/callback`;
  }

  /** Only configured and explicitly enabled initial-release providers. */
  async listProviders(
    _journey: ExternalAuthJourney = "login",
  ): Promise<{ providers: OAuthProviderName[] }> {
    const readiness = await Promise.all(
      VISIBLE_PROVIDERS.map(async (provider) => ({
        provider,
        ready: Boolean(await this.providerConfig(provider)),
      })),
    );
    return {
      providers: readiness
        .filter((entry) => entry.ready)
        .map((entry) => entry.provider),
    };
  }

  async buildAuthorizationUrl(
    provider: OAuthProviderName,
    tenantSlug?: string,
    returnTo?: string,
    journey: ExternalAuthJourney = "login",
    linkContext?: { userId: string; tenantId: string },
  ): Promise<string> {
    const config = await this.requireProviderConfig(provider);
    const safeReturn = safeReturnTo(returnTo);
    await this.assertExternalAuthAllowed(safeReturn);
    const nonce = randomBytes(24).toString("base64url");
    const codeVerifier = randomBytes(48).toString("base64url");
    const codeChallenge = createHash("sha256")
      .update(codeVerifier)
      .digest("base64url");
    const state = await this.externalAuthStore.createTransaction({
      provider,
      journey,
      tenantSlug: tenantSlug || null,
      returnTo: safeReturn,
      nonce,
      codeVerifier,
      linkUserId: linkContext?.userId,
      linkTenantId: linkContext?.tenantId,
    });

    const params = new URLSearchParams({
      client_id: config.clientId,
      redirect_uri: this.redirectUri(provider),
      response_type: "code",
      scope: config.scope,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    });
    if (provider !== "github") params.set("nonce", nonce);
    if (provider === "google") {
      params.set("access_type", "online");
      params.set("prompt", "select_account");
    }
    return `${config.authorizeUrl}?${params.toString()}`;
  }

  async buildLinkAuthorizationUrl(
    provider: OAuthProviderName,
    userId: string,
    tenantId: string,
    sid: string,
    returnTo = "/oidc/account",
  ): Promise<string> {
    await this.requireFreshSession(userId, tenantId, sid);
    return this.buildAuthorizationUrl(
      provider,
      undefined,
      returnTo,
      "link",
      { userId, tenantId },
    );
  }

  async handleCallback(
    provider: OAuthProviderName,
    code: string,
    state: string,
    context?: SessionContext,
  ): Promise<OAuthCallbackResult> {
    const transaction = await this.externalAuthStore.consumeTransaction(state);
    if (!transaction || transaction.provider !== provider) {
      throw new UnauthorizedException("Invalid or expired sign-in state.");
    }

    const profile = await this.exchangeAndFetchProfile(
      provider,
      code,
      transaction.nonce,
      transaction.codeVerifier,
    );
    if (!profile.subject || !profile.email || !profile.emailVerified) {
      throw new UnauthorizedException(
        "Your identity provider did not supply a verified email address.",
      );
    }

    if (transaction.journey === "link") {
      if (!transaction.linkUserId || !transaction.linkTenantId) {
        throw new UnauthorizedException("Account-linking state is incomplete.");
      }
      const linkedUser = await this.linkExternalIdentity(
        provider,
        profile,
        transaction.linkUserId,
        transaction.linkTenantId,
      );
      const session = await this.authService.issueSession(linkedUser, context);
      return {
        kind: "session",
        ...session,
        returnTo: transaction.returnTo,
      } as OAuthCallbackResult;
    }

    const user = await this.resolveLinkedUser(provider, profile);
    if (user) {
      const session = await this.authService.issueSession(user, context);
      return {
        kind: "session",
        ...session,
        returnTo: transaction.returnTo,
      } as OAuthCallbackResult;
    }

    const matches = await prisma.$queryRaw<Array<{ id: string }>>`
      SELECT id FROM auth_lookup_user_tenants(${profile.email})
    `;
    if (matches.length > 0) {
      throw new UnauthorizedException(
        "An existing UniERP account uses this email. Sign in with an existing method, then connect this provider in Account Center.",
      );
    }

    const registrationTicket = await this.externalAuthStore.createRegistration({
      provider,
      subject: profile.subject,
      email: profile.email,
      emailVerified: true,
      firstName: profile.firstName,
      lastName: profile.lastName,
      returnTo: transaction.returnTo,
    });
    return {
      kind: "registration",
      registrationTicket,
      returnTo: transaction.returnTo,
    };
  }

  async getRegistrationProfile(
    ticket: string,
  ): Promise<ExternalRegistrationProfile | null> {
    return this.externalAuthStore.peekRegistration(ticket);
  }

  async getConnectedProviders(
    userId: string,
    tenantId: string,
  ): Promise<OAuthProviderName[]> {
    return runWithTenantSession({ tenantId, userId }, async () => {
      const identities = await idpPrisma.userIdentity.findMany({
        where: { userId, tenantId },
        select: { provider: true },
      });
      return identities
        .map((identity) => identity.provider)
        .filter((provider): provider is OAuthProviderName =>
          VISIBLE_PROVIDERS.includes(provider as OAuthProviderName),
        );
    });
  }

  async unlinkProvider(
    provider: OAuthProviderName,
    userId: string,
    tenantId: string,
    sid: string,
  ): Promise<{ connected: OAuthProviderName[] }> {
    await this.requireFreshSession(userId, tenantId, sid);
    return runWithTenantSession({ tenantId, userId }, async () => {
      const [user, identities] = await Promise.all([
        idpPrisma.user.findFirst({ where: { id: userId, tenantId } }),
        idpPrisma.userIdentity.findMany({
          where: { userId, tenantId },
          select: { provider: true },
        }),
      ]);
      if (!user) throw new UnauthorizedException("Account is unavailable.");
      const hasProvider = identities.some(
        (identity) => identity.provider === provider,
      );
      if (!hasProvider) {
        return { connected: await this.getConnectedProviders(userId, tenantId) };
      }
      if (!user.passwordHash && identities.length <= 1) {
        throw new BadRequestException(
          "Add another sign-in method before disconnecting your only provider.",
        );
      }
      await idpPrisma.userIdentity.deleteMany({
        where: { userId, tenantId, provider },
      });
      await emitAuthAudit({
        tenantId,
        userId,
        action: "EXTERNAL_IDENTITY_UNLINKED",
        entityType: "UserIdentity",
        entityId: `${provider}:${userId}`,
        changes: { provider },
      });
      return {
        connected: identities
          .map((identity) => identity.provider)
          .filter(
            (candidate): candidate is OAuthProviderName =>
              candidate !== provider &&
              VISIBLE_PROVIDERS.includes(candidate as OAuthProviderName),
          ),
      };
    });
  }

  async completeExternalRegistration(
    ticket: string,
    input: {
      organizationName: string;
      firstName?: string;
      lastName?: string;
      termsAccepted: true;
    },
    context?: SessionContext,
  ): Promise<Record<string, unknown> & { returnTo: string }> {
    const organizationName = input.organizationName.trim();
    if (!organizationName || organizationName.length > 200) {
      throw new BadRequestException(
        "Organization name is required and must be 200 characters or fewer.",
      );
    }
    const profile = await this.externalAuthStore.consumeRegistration(ticket);
    if (!profile) {
      throw new UnauthorizedException(
        "External registration expired. Please choose your provider again.",
      );
    }
    const result = await this.authService.register(
      {
        organizationName,
        firstName: input.firstName?.trim() || profile.firstName || "User",
        lastName: input.lastName?.trim() || profile.lastName || "",
        email: profile.email,
        termsAccepted: true,
        externalIdentity: {
          provider: profile.provider,
          subject: profile.subject,
        },
      },
      context,
    );

    const user = await runWithTenantSession(
      { tenantId: result.tenant.id, userId: result.user.id },
      () =>
        idpPrisma.user.findFirst({
          where: { id: result.user.id, status: "ACTIVE" },
        }),
    );
    if (!user) throw new UnauthorizedException("Registered account is unavailable.");
    const session = await this.authService.issueSession(user, context);
    return { ...session, returnTo: profile.returnTo };
  }

  private async providerConfig(
    provider: OAuthProviderName,
  ): Promise<ProviderConfig | null> {
    const creds = await this.platformCredentialsService.get(`${provider}-oauth`);
    const clientId = creds.clientId;
    const clientSecret = creds.clientSecret;
    if (!clientId || !clientSecret || isExplicitlyDisabled(creds.enabled)) {
      return null;
    }

    if (provider === "google") {
      return {
        authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
        tokenUrl: "https://oauth2.googleapis.com/token",
        issuer: "https://accounts.google.com",
        jwksUrl: "https://www.googleapis.com/oauth2/v3/certs",
        clientId,
        clientSecret,
        scope: "openid email profile",
      };
    }
    if (provider === "microsoft") {
      const tenant = creds.tenantId || "common";
      return {
        authorizeUrl: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`,
        tokenUrl: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
        jwksUrl: `https://login.microsoftonline.com/${tenant}/discovery/v2.0/keys`,
        microsoftTenant: tenant,
        clientId,
        clientSecret,
        scope: "openid email profile",
      };
    }
    return {
      authorizeUrl: "https://github.com/login/oauth/authorize",
      tokenUrl: "https://github.com/login/oauth/access_token",
      clientId,
      clientSecret,
      scope: "read:user user:email",
    };
  }

  private async assertExternalAuthAllowed(returnTo: string): Promise<void> {
    try {
      const url = new URL(returnTo, "http://idp.local");
      const clientId = url.searchParams.get("client_id");
      if (!clientId) return;
      const client = await idpPrisma.oAuthClient.findUnique({
        where: { clientId },
        select: { platformCode: true },
      });
      if (!client?.platformCode) return;
      const platform = await idpPrisma.platform.findUnique({
        where: { code: client.platformCode },
        select: { audience: true },
      });
      if (platform?.audience === "INTERNAL") {
        throw new UnauthorizedException(
          "External account sign-in is not permitted for this platform.",
        );
      }
    } catch (err) {
      if (err instanceof UnauthorizedException) throw err;
      // Malformed/unresolvable return intents are already reduced to a safe
      // root by safeReturnTo and contain no client authority to evaluate.
    }
  }

  private async requireProviderConfig(
    provider: OAuthProviderName,
  ): Promise<ProviderConfig> {
    const config = await this.providerConfig(provider);
    if (!config) {
      throw new BadRequestException(
        `${provider} sign-in is not configured or enabled on this server.`,
      );
    }
    return config;
  }

  private async exchangeAndFetchProfile(
    provider: OAuthProviderName,
    code: string,
    nonce: string,
    codeVerifier: string,
  ): Promise<OAuthProfile> {
    const config = await this.requireProviderConfig(provider);
    if (provider === "github") {
      return this.fetchGitHubProfile(config, code, codeVerifier);
    }

    const tokenRes = await fetch(config.tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: config.clientId,
        client_secret: config.clientSecret,
        code,
        code_verifier: codeVerifier,
        grant_type: "authorization_code",
        redirect_uri: this.redirectUri(provider),
      }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!tokenRes.ok) {
      this.logger.warn(`[oauth] ${provider} code exchange failed: ${tokenRes.status}`);
      throw new UnauthorizedException("Sign-in could not be completed.");
    }
    const tokens = (await tokenRes.json()) as { id_token?: string };
    if (!tokens.id_token) {
      throw new UnauthorizedException("Identity provider returned no identity token.");
    }

    const claims = await this.verifyOidcToken(
      provider,
      tokens.id_token,
      config,
      nonce,
    );
    if (provider === "google") {
      return {
        subject: String(claims.sub || ""),
        email: String(claims.email || "").toLowerCase(),
        emailVerified: claims.email_verified === true,
        firstName: stringClaim(claims.given_name),
        lastName: stringClaim(claims.family_name),
      };
    }

    const email = String(claims.email || claims.preferred_username || "").toLowerCase();
    const name = String(claims.name || "").trim();
    return {
      subject: `${String(claims.tid || "")}:${String(claims.oid || claims.sub || "")}`,
      email,
      emailVerified: Boolean(email && email.includes("@")),
      firstName: stringClaim(claims.given_name) || name.split(" ")[0] || undefined,
      lastName:
        stringClaim(claims.family_name) ||
        name.split(" ").slice(1).join(" ") ||
        undefined,
    };
  }

  private async verifyOidcToken(
    provider: "google" | "microsoft",
    idToken: string,
    config: ProviderConfig,
    nonce: string,
  ): Promise<JWTPayload> {
    if (!config.jwksUrl) throw new UnauthorizedException("Provider keys unavailable.");
    let issuer: string | string[];
    if (provider === "google") {
      issuer = ["https://accounts.google.com", "accounts.google.com"];
    } else {
      const unverified = decodeJwt(idToken);
      const tenantId = String(unverified.tid || "");
      if (!/^[0-9a-f-]{36}$/i.test(tenantId)) {
        throw new UnauthorizedException("Microsoft tenant claim is invalid.");
      }
      const configuredTenant = config.microsoftTenant || "common";
      if (
        !["common", "organizations", "consumers"].includes(configuredTenant) &&
        configuredTenant.toLowerCase() !== tenantId.toLowerCase()
      ) {
        throw new UnauthorizedException("Microsoft tenant is not allowed.");
      }
      issuer = `https://login.microsoftonline.com/${tenantId}/v2.0`;
    }

    try {
      const keySet = this.keySetFor(config.jwksUrl);
      const verified = await jwtVerify(idToken, keySet, {
        algorithms: ["RS256"],
        issuer,
        audience: config.clientId,
        clockTolerance: 30,
      });
      if (verified.payload.nonce !== nonce) {
        throw new UnauthorizedException("Identity response nonce is invalid.");
      }
      return verified.payload;
    } catch (err) {
      if (err instanceof UnauthorizedException) throw err;
      this.logger.warn(
        `[oauth] ${provider} ID token verification failed: ${err instanceof Error ? err.message : "unknown verification error"}`,
      );
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

  private async fetchGitHubProfile(
    config: ProviderConfig,
    code: string,
    codeVerifier: string,
  ): Promise<OAuthProfile> {
    const tokenRes = await fetch(config.tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        client_id: config.clientId,
        client_secret: config.clientSecret,
        code,
        code_verifier: codeVerifier,
        redirect_uri: this.redirectUri("github"),
      }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!tokenRes.ok) {
      this.logger.warn(`[oauth] github code exchange failed: ${tokenRes.status}`);
      throw new UnauthorizedException("Sign-in could not be completed.");
    }
    const tokenData = (await tokenRes.json()) as { access_token?: string };
    if (!tokenData.access_token) {
      throw new UnauthorizedException("GitHub returned no access token.");
    }
    const headers = {
      Authorization: `Bearer ${tokenData.access_token}`,
      "User-Agent": "UniERP-IdP",
      Accept: "application/vnd.github+json",
    };
    const userRes = await fetch("https://api.github.com/user", {
      headers,
      signal: AbortSignal.timeout(10_000),
    });
    if (!userRes.ok) {
      throw new UnauthorizedException("Could not fetch GitHub user profile.");
    }
    const user = (await userRes.json()) as {
      id?: number;
      name?: string;
      login?: string;
    };
    const emailsRes = await fetch("https://api.github.com/user/emails", {
      headers,
      signal: AbortSignal.timeout(10_000),
    });
    if (!emailsRes.ok) {
      throw new UnauthorizedException("GitHub did not provide a verified email.");
    }
    const emails = (await emailsRes.json()) as Array<{
      email: string;
      primary: boolean;
      verified: boolean;
    }>;
    const selected =
      emails.find((email) => email.primary && email.verified) ||
      emails.find((email) => email.verified);
    if (!selected || !user.id) {
      throw new UnauthorizedException("GitHub did not provide a verified email.");
    }
    const name = (user.name || user.login || "").trim();
    return {
      subject: String(user.id),
      email: selected.email.toLowerCase(),
      emailVerified: true,
      firstName: name.split(" ")[0] || user.login,
      lastName: name.split(" ").slice(1).join(" ") || undefined,
    };
  }

  private async resolveLinkedUser(
    provider: OAuthProviderName,
    profile: OAuthProfile,
  ) {
    const linked = await prisma.$queryRaw<
      Array<{ user_id: string; tenant_id: string }>
    >`SELECT user_id, tenant_id FROM auth_lookup_oauth_identity(${provider}, ${profile.subject})`;
    const userId = linked[0]?.user_id;
    const tenantId = linked[0]?.tenant_id;
    if (!userId || !tenantId) return null;

    return runWithTenantSession({ tenantId, userId }, async () => {
      const user = await idpPrisma.user.findFirst({
        where: { id: userId, status: "ACTIVE" },
      });
      if (!user) throw new UnauthorizedException("Account is inactive or missing.");
      if (!user.emailVerifiedAt && profile.email === user.email.toLowerCase()) {
        return idpPrisma.user.update({
          where: { id: user.id },
          data: { emailVerifiedAt: new Date() },
        });
      }
      return user;
    });
  }

  private async linkExternalIdentity(
    provider: OAuthProviderName,
    profile: OAuthProfile,
    userId: string,
    tenantId: string,
  ) {
    const existing = await prisma.$queryRaw<
      Array<{ user_id: string; tenant_id: string }>
    >`SELECT user_id, tenant_id FROM auth_lookup_oauth_identity(${provider}, ${profile.subject})`;
    if (
      existing.length &&
      (existing[0]?.user_id !== userId || existing[0]?.tenant_id !== tenantId)
    ) {
      throw new BadRequestException(
        "This provider account is already connected to another UniERP account.",
      );
    }

    return runWithTenantSession({ tenantId, userId }, async () => {
      const user = await idpPrisma.user.findFirst({
        where: { id: userId, tenantId, status: "ACTIVE" },
      });
      if (!user) throw new UnauthorizedException("Account is unavailable.");
      if (!existing.length) {
        await idpPrisma.userIdentity.create({
          data: {
            tenantId,
            userId,
            provider,
            subject: profile.subject,
            email: profile.email,
          },
        });
        await emitAuthAudit({
          tenantId,
          userId,
          action: "EXTERNAL_IDENTITY_LINKED",
          entityType: "UserIdentity",
          entityId: `${provider}:${userId}`,
          changes: { provider },
        });
      }
      return user;
    });
  }

  private async requireFreshSession(
    userId: string,
    tenantId: string,
    sid: string,
  ): Promise<void> {
    const session = await runWithTenantSession({ tenantId, userId }, () =>
      idpPrisma.userSession.findUnique({ where: { id: sid } }),
    );
    const tenMinutesAgo = Date.now() - 10 * 60 * 1000;
    if (
      !session ||
      !session.isActive ||
      session.userId !== userId ||
      session.tenantId !== tenantId ||
      session.startedAt.getTime() < tenMinutesAgo
    ) {
      throw new UnauthorizedException(
        "Recent authentication is required to change connected accounts.",
      );
    }
  }
}

function isExplicitlyDisabled(value?: string): boolean {
  return value?.trim().toLowerCase() === "false";
}

function stringClaim(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function safeReturnTo(raw?: string): string {
  const defaultTarget =
    process.env.TENANT_APP_URL
      ? `${process.env.TENANT_APP_URL}/apps`
      : process.env.PLATFORM_WIZARD_URL || "http://localhost:4000";

  if (!raw || raw === "/" || raw === "") return defaultTarget;
  if (raw.startsWith("/oidc/")) return raw;
  if (raw.startsWith("/") && !raw.startsWith("//")) {
    const tenantAppUrl = process.env.TENANT_APP_URL || "http://localhost:4003";
    return `${tenantAppUrl.replace(/\/$/, "")}${raw}`;
  }
  try {
    const url = new URL(raw);
    if (
      url.hostname === "localhost" ||
      url.hostname === "127.0.0.1" ||
      url.hostname.endsWith(".uni-erp.com") ||
      url.hostname.endsWith(".unierp.internal") ||
      url.hostname.endsWith(".unierp.cloud")
    ) {
      return url.toString();
    }
  } catch {
    // Fall through to the safe root.
  }
  return defaultTarget;
}
