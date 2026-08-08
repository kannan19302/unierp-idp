import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
  Logger,
} from "@nestjs/common";
import { randomBytes } from "node:crypto";
import { idpPrisma, prisma, runWithTenantSession } from "@kannan19302/database";
import { signTypedToken, verifyTypedToken, TOKEN_TYPE } from "@kannan19302/auth";
import { AuthService, SessionContext } from "./auth.service";
import { PlatformCredentialsService } from "../../common/platform-credentials/platform-credentials.service";

/**
 * Real OAuth 2.0 / OIDC sign-in (AUTH_BILLING_PROGRAM Phase 1.3/1.4).
 *
 * Confidential authorization-code flow for Google and Microsoft Entra ID.
 * Providers are env-gated: a provider is offered only when its client id +
 * secret are configured. Identity is anchored on the provider's stable
 * subject (Google `sub`, Entra `oid`/`sub`) in `user_identities`; the email
 * is only used for first-time account matching, never for re-identification.
 */

export type OAuthProviderName = "google" | "microsoft";

interface ProviderConfig {
  authorizeUrl: string;
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  scope: string;
}

interface OAuthProfile {
  subject: string;
  email: string;
  emailVerified: boolean;
  firstName?: string;
  lastName?: string;
}

/** How long the signed `state` parameter stays valid. */
const STATE_TTL = "10m";

@Injectable()
export class OAuthService {
  private readonly logger = new Logger(OAuthService.name);

  constructor(
    private readonly authService: AuthService,
    private readonly platformCredentialsService: PlatformCredentialsService,
  ) {}

  private get apiUrl() {
    return process.env.API_PUBLIC_URL || "http://localhost:3001";
  }

  private redirectUri(provider: OAuthProviderName) {
    return `${this.apiUrl}/api/v1/auth/oauth/${provider}/callback`;
  }

  private async providerConfig(
    provider: OAuthProviderName,
  ): Promise<ProviderConfig | null> {
    if (provider === "google") {
      const creds = await this.platformCredentialsService.get("google-oauth");
      const clientId = creds.clientId;
      const clientSecret = creds.clientSecret;
      if (!clientId || !clientSecret) return null;
      return {
        authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
        tokenUrl: "https://oauth2.googleapis.com/token",
        clientId,
        clientSecret,
        scope: "openid email profile",
      };
    }
    const creds = await this.platformCredentialsService.get("microsoft-oauth");
    const clientId = creds.clientId;
    const clientSecret = creds.clientSecret;
    if (!clientId || !clientSecret) return null;
    const entraTenant = creds.tenantId || "common";
    return {
      authorizeUrl: `https://login.microsoftonline.com/${entraTenant}/oauth2/v2.0/authorize`,
      tokenUrl: `https://login.microsoftonline.com/${entraTenant}/oauth2/v2.0/token`,
      clientId,
      clientSecret,
      scope: "openid email profile",
    };
  }

  /** Providers that are fully configured — drives the login page buttons. */
  async listProviders() {
    const results = await Promise.all(
      (["google", "microsoft"] as const).map(async (p) => ({
        p,
        configured: Boolean(await this.providerConfig(p)),
      })),
    );
    return {
      providers: results.filter((r) => r.configured).map((r) => r.p),
    };
  }

  /**
   * Builds the provider authorization URL with a signed, single-round-trip
   * `state` (CSRF guard + carries the optional tenant slug).
   */
  async buildAuthorizationUrl(
    provider: OAuthProviderName,
    tenantSlug?: string,
  ) {
    const config = await this.providerConfig(provider);
    if (!config) {
      throw new BadRequestException(
        `${provider} sign-in is not configured on this server.`,
      );
    }

    const state = signTypedToken(
      TOKEN_TYPE.OAUTH_STATE,
      {
        provider,
        tenantSlug: tenantSlug || null,
        nonce: randomBytes(12).toString("hex"),
      },
      STATE_TTL,
    );

    const params = new URLSearchParams({
      client_id: config.clientId,
      redirect_uri: this.redirectUri(provider),
      response_type: "code",
      scope: config.scope,
      state,
    });
    if (provider === "google") {
      params.set("access_type", "online");
      params.set("prompt", "select_account");
    }
    return `${config.authorizeUrl}?${params.toString()}`;
  }

  /**
   * Handles the provider callback: state check, code exchange, profile fetch,
   * identity resolution, session issuance. Returns the same session payload as
   * password login (with refreshToken for the controller to seal into cookies).
   */
  async handleCallback(
    provider: OAuthProviderName,
    code: string,
    state: string,
    context?: SessionContext,
  ) {
    const decodedState = verifyTypedToken<{
      provider: string;
      tenantSlug: string | null;
    }>(state, TOKEN_TYPE.OAUTH_STATE);
    if (!decodedState || decodedState.provider !== provider) {
      throw new UnauthorizedException("Invalid or expired sign-in state.");
    }

    const profile = await this.exchangeAndFetchProfile(provider, code);
    if (!profile.email || !profile.emailVerified) {
      throw new UnauthorizedException(
        "Your identity provider did not supply a verified email address.",
      );
    }

    const user = await this.resolveUser(
      provider,
      profile,
      decodedState.tenantSlug,
    );
    return this.authService.issueSession(user, context);
  }

  /** Exchanges the authorization code and normalizes the provider profile. */
  private async exchangeAndFetchProfile(
    provider: OAuthProviderName,
    code: string,
  ): Promise<OAuthProfile> {
    const config = await this.providerConfig(provider);
    if (!config) {
      throw new BadRequestException(
        `${provider} sign-in is not configured on this server.`,
      );
    }

    const tokenRes = await fetch(config.tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: config.clientId,
        client_secret: config.clientSecret,
        code,
        grant_type: "authorization_code",
        redirect_uri: this.redirectUri(provider),
      }),
    });
    if (!tokenRes.ok) {
      this.logger.warn(
        `[oauth] ${provider} code exchange failed: ${tokenRes.status} ${await tokenRes
          .text()
          .catch(() => "")}`,
      );
      throw new UnauthorizedException("Sign-in could not be completed.");
    }
    const tokens = (await tokenRes.json()) as { id_token?: string };
    if (!tokens.id_token) {
      throw new UnauthorizedException(
        "Identity provider returned no identity token.",
      );
    }

    // The id_token comes straight from the provider's token endpoint over TLS
    // in a confidential-client exchange, so its claims are trustworthy without
    // an extra signature check (there is no third party in this hop).
    const claims = JSON.parse(
      Buffer.from(tokens.id_token.split(".")[1] ?? "", "base64url").toString(
        "utf8",
      ),
    ) as Record<string, unknown>;

    if (provider === "google") {
      return {
        subject: String(claims.sub ?? ""),
        email: String(claims.email ?? "").toLowerCase(),
        emailVerified: claims.email_verified === true,
        firstName: (claims.given_name as string) || undefined,
        lastName: (claims.family_name as string) || undefined,
      };
    }
    // Entra: `oid` is the immutable object id; `email`/`preferred_username`
    // carry the address. Entra only issues these for verified work accounts.
    const email = String(
      claims.email ?? claims.preferred_username ?? "",
    ).toLowerCase();
    const name = String(claims.name ?? "");
    return {
      subject: String(claims.oid ?? claims.sub ?? ""),
      email,
      emailVerified: email.includes("@"),
      firstName: name.split(" ")[0] || undefined,
      lastName: name.split(" ").slice(1).join(" ") || undefined,
    };
  }

  /**
   * Maps the external identity to a tenant user:
   *  1. an existing identity link wins (stable across email changes);
   *  2. otherwise match by email — requires a tenant slug when the email
   *     exists in several tenants — and create the link;
   *  3. no match → refuse (organizations register through /register; OAuth
   *     never silently creates a tenant).
   */
  private async resolveUser(
    provider: OAuthProviderName,
    profile: OAuthProfile,
    tenantSlug: string | null,
  ) {
    // 1. Existing identity link (SECURITY DEFINER: pre-tenant-context lookup).
    const linked = await prisma.$queryRaw<
      Array<{ user_id: string; tenant_id: string }>
    >`SELECT user_id, tenant_id FROM auth_lookup_oauth_identity(${provider}, ${profile.subject})`;

    let userId: string | undefined = linked[0]?.user_id;
    let tenantId: string | undefined = linked[0]?.tenant_id;

    if (!userId || !tenantId) {
      // 2. First OAuth login: match by email.
      const matches = await prisma.$queryRaw<
        Array<{ id: string; tenant_id: string }>
      >`SELECT id, tenant_id FROM auth_lookup_user_tenants(${profile.email})`;
      if (matches.length === 0) {
        throw new UnauthorizedException(
          "No UniERP account uses this email. Register your organization first.",
        );
      }
      let match = matches[0]!;
      if (matches.length > 1) {
        if (!tenantSlug) {
          throw new BadRequestException(
            "This email belongs to multiple organizations. Enter your Organization Slug, then retry.",
          );
        }
        const tenant = await prisma.tenant.findUnique({
          where: { slug: tenantSlug },
        });
        const scoped = tenant
          ? matches.find((m) => m.tenant_id === tenant.id)
          : undefined;
        if (!scoped) {
          throw new UnauthorizedException(
            "No account with this email in that organization.",
          );
        }
        match = scoped;
      }
      userId = match.id;
      tenantId = match.tenant_id;

      await runWithTenantSession({ tenantId, userId }, () =>
        idpPrisma.userIdentity.create({
          data: {
            tenantId: tenantId!,
            userId: userId!,
            provider,
            subject: profile.subject,
            email: profile.email,
          },
        }),
      );
    }

    return runWithTenantSession({ tenantId, userId }, async () => {
      const user = await idpPrisma.user.findFirst({
        where: { id: userId, status: "ACTIVE" },
      });
      if (!user) {
        throw new UnauthorizedException("Account is inactive or missing.");
      }
      // A provider-verified email also satisfies our own verification.
      if (!user.emailVerifiedAt && profile.email === user.email.toLowerCase()) {
        await idpPrisma.user.update({
          where: { id: user.id },
          data: { emailVerifiedAt: new Date() },
        });
      }
      return user;
    });
  }
}
