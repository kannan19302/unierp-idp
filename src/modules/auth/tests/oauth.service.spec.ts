import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  SignJWT,
} from "jose";

vi.mock("@kannan19302/database", () => ({
  idpPrisma: {
    user: { findFirst: vi.fn(), update: vi.fn() },
    userIdentity: {
      findMany: vi.fn().mockResolvedValue([]),
      create: vi.fn(),
      deleteMany: vi.fn(),
    },
    userSession: { findUnique: vi.fn() },
    oAuthClient: { findUnique: vi.fn().mockResolvedValue(null) },
    platform: { findUnique: vi.fn().mockResolvedValue(null) },
  },
  prisma: {
    $queryRaw: vi.fn().mockResolvedValue([]),
    tenant: { findUnique: vi.fn() },
    user: { findFirst: vi.fn(), update: vi.fn() },
    userIdentity: { create: vi.fn() },
  },
  runWithTenantSession: vi.fn((_s: unknown, fn: () => unknown) => fn()),
}));

import { OAuthService } from "../oauth.service";
import { AuthService } from "../auth.service";
import { PlatformCredentialsService } from "../../../common/platform-credentials/platform-credentials.service";
import { ExternalAuthStore } from "../external-auth.store";
import { prisma } from "@kannan19302/database";

describe("OAuthService", () => {
  let service: OAuthService;
  let externalAuthStore: ExternalAuthStore;
  const issueSession = vi.fn().mockResolvedValue({ token: "t" });

  // Minimal stand-in that reproduces the real service's DB-first/env-fallback
  // behavior against process.env, without touching the database.
  const platformCredentialsService = {
    get: vi.fn(async (provider: string) => {
      if (provider === "google-oauth") {
        return {
          enabled: process.env.GOOGLE_OAUTH_ENABLED ?? "",
          clientId: process.env.GOOGLE_OAUTH_CLIENT_ID ?? "",
          clientSecret: process.env.GOOGLE_OAUTH_CLIENT_SECRET ?? "",
        };
      }
      if (provider === "microsoft-oauth") {
        return {
          enabled: process.env.MICROSOFT_OAUTH_ENABLED ?? "",
          clientId: process.env.MICROSOFT_OAUTH_CLIENT_ID ?? "",
          clientSecret: process.env.MICROSOFT_OAUTH_CLIENT_SECRET ?? "",
          tenantId: process.env.MICROSOFT_OAUTH_TENANT ?? "",
        };
      }
      if (provider === "github-oauth") {
        return {
          enabled: process.env.GITHUB_OAUTH_ENABLED ?? "",
          clientId: process.env.GITHUB_OAUTH_CLIENT_ID ?? "",
          clientSecret: process.env.GITHUB_OAUTH_CLIENT_SECRET ?? "",
        };
      }
      return {};
    }),
  } as unknown as PlatformCredentialsService;

  beforeEach(() => {
    service = new OAuthService(
      { issueSession } as unknown as AuthService,
      platformCredentialsService,
      (externalAuthStore = new ExternalAuthStore()),
    );
    delete process.env.GOOGLE_OAUTH_CLIENT_ID;
    delete process.env.GOOGLE_OAUTH_CLIENT_SECRET;
    delete process.env.MICROSOFT_OAUTH_CLIENT_ID;
    delete process.env.MICROSOFT_OAUTH_CLIENT_SECRET;
    delete process.env.MICROSOFT_OAUTH_TENANT;
    delete process.env.GITHUB_OAUTH_CLIENT_ID;
    delete process.env.GITHUB_OAUTH_CLIENT_SECRET;
    delete process.env.MICROSOFT_OAUTH_CLIENT_ID;
    delete process.env.MICROSOFT_OAUTH_CLIENT_SECRET;
    delete process.env.MICROSOFT_OAUTH_TENANT;
    delete process.env.GOOGLE_OAUTH_ENABLED;
    delete process.env.MICROSOFT_OAUTH_ENABLED;
    delete process.env.GITHUB_OAUTH_ENABLED;
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    delete process.env.GOOGLE_OAUTH_CLIENT_ID;
    delete process.env.GOOGLE_OAUTH_CLIENT_SECRET;
    delete process.env.GITHUB_OAUTH_CLIENT_ID;
    delete process.env.GITHUB_OAUTH_CLIENT_SECRET;
    delete process.env.GOOGLE_OAUTH_ENABLED;
    delete process.env.MICROSOFT_OAUTH_ENABLED;
    delete process.env.GITHUB_OAUTH_ENABLED;
  });

  it("advertises no providers when nothing is configured", async () => {
    await expect(service.listProviders()).resolves.toEqual({ providers: [] });
  });

  it("advertises google once its credentials are configured", async () => {
    process.env.GOOGLE_OAUTH_CLIENT_ID = "cid";
    process.env.GOOGLE_OAUTH_CLIENT_SECRET = "sec";
    await expect(service.listProviders()).resolves.toEqual({
      providers: ["google"],
    });
  });

  it("refuses to build an authorization URL for an unconfigured provider", async () => {
    await expect(service.buildAuthorizationUrl("google")).rejects.toThrow(
      "not configured",
    );
  });

  it("builds a Google authorization URL carrying client id, nonce, PKCE and opaque state", async () => {
    process.env.GOOGLE_OAUTH_CLIENT_ID = "cid";
    process.env.GOOGLE_OAUTH_CLIENT_SECRET = "sec";

    const url = new URL(await service.buildAuthorizationUrl("google", "acme"));
    expect(url.origin + url.pathname).toBe(
      "https://accounts.google.com/o/oauth2/v2/auth",
    );
    expect(url.searchParams.get("client_id")).toBe("cid");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("redirect_uri")).toContain(
      "/api/v1/auth/oauth/google/callback",
    );
    expect(url.searchParams.get("state")).toMatch(/^[A-Za-z0-9_-]{40,64}$/);
    expect(url.searchParams.get("nonce")).toBeTruthy();
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("code_challenge")).toBeTruthy();
  });

  it("rejects a callback whose state is invalid or for another provider", async () => {
    process.env.GOOGLE_OAUTH_CLIENT_ID = "cid";
    process.env.GOOGLE_OAUTH_CLIENT_SECRET = "sec";

    await expect(
      service.handleCallback("google", "code", "not-a-jwt"),
    ).rejects.toThrow("Invalid or expired sign-in state");

    process.env.MICROSOFT_OAUTH_CLIENT_ID = "cid2";
    process.env.MICROSOFT_OAUTH_CLIENT_SECRET = "sec2";
    const microsoftState = new URL(
      await service.buildAuthorizationUrl("microsoft"),
    ).searchParams.get("state")!;
    await expect(
      service.handleCallback("google", "code", microsoftState),
    ).rejects.toThrow("Invalid or expired sign-in state");
  });

  it("does not allow social sign-in to an internal provider platform", async () => {
    process.env.GOOGLE_OAUTH_CLIENT_ID = "cid";
    process.env.GOOGLE_OAUTH_CLIENT_SECRET = "sec";
    const { idpPrisma } = await import("@kannan19302/database");
    vi.mocked(idpPrisma.oAuthClient.findUnique).mockResolvedValueOnce({
      platformCode: "P2",
    } as never);
    vi.mocked(idpPrisma.platform.findUnique).mockResolvedValueOnce({
      audience: "INTERNAL",
    } as never);

    await expect(
      service.buildAuthorizationUrl(
        "google",
        undefined,
        "/oidc/authorize?client_id=provider-admin",
      ),
    ).rejects.toThrow("not permitted for this platform");
  });

  it("does not advertise explicitly disabled providers", async () => {
    process.env.GOOGLE_OAUTH_CLIENT_ID = "cid";
    process.env.GOOGLE_OAUTH_CLIENT_SECRET = "sec";
    process.env.GOOGLE_OAUTH_ENABLED = "false";
    await expect(service.listProviders()).resolves.toEqual({ providers: [] });
    delete process.env.GOOGLE_OAUTH_ENABLED;
  });

  it("consumes external auth state exactly once", async () => {
    const state = await externalAuthStore.createTransaction({
      provider: "google",
      journey: "login",
      tenantSlug: null,
      returnTo: "/",
      nonce: "n",
      codeVerifier: "v",
    });
    await expect(externalAuthStore.consumeTransaction(state)).resolves.toMatchObject({
      provider: "google",
    });
    await expect(externalAuthStore.consumeTransaction(state)).resolves.toBeNull();
  });

  it("creates a recent-auth bound account-linking transaction", async () => {
    process.env.GOOGLE_OAUTH_CLIENT_ID = "cid";
    process.env.GOOGLE_OAUTH_CLIENT_SECRET = "sec";
    const { idpPrisma } = await import("@kannan19302/database");
    vi.mocked(idpPrisma.userSession.findUnique).mockResolvedValueOnce({
      id: "session-1",
      userId: "user-1",
      tenantId: "tenant-1",
      isActive: true,
      startedAt: new Date(),
    } as never);

    const url = new URL(
      await service.buildLinkAuthorizationUrl(
        "google",
        "user-1",
        "tenant-1",
        "session-1",
      ),
    );
    const state = url.searchParams.get("state")!;
    await expect(externalAuthStore.consumeTransaction(state)).resolves.toMatchObject({
      journey: "link",
      linkUserId: "user-1",
      linkTenantId: "tenant-1",
    });
  });

  it("rejects connected-account changes from a stale session", async () => {
    process.env.GOOGLE_OAUTH_CLIENT_ID = "cid";
    process.env.GOOGLE_OAUTH_CLIENT_SECRET = "sec";
    const { idpPrisma } = await import("@kannan19302/database");
    vi.mocked(idpPrisma.userSession.findUnique).mockResolvedValueOnce({
      id: "session-1",
      userId: "user-1",
      tenantId: "tenant-1",
      isActive: true,
      startedAt: new Date(Date.now() - 11 * 60 * 1000),
    } as never);

    await expect(
      service.buildLinkAuthorizationUrl(
        "google",
        "user-1",
        "tenant-1",
        "session-1",
      ),
    ).rejects.toThrow("Recent authentication is required");
  });

  it("links a verified provider to the recently authenticated account", async () => {
    const { idpPrisma } = await import("@kannan19302/database");
    const state = await externalAuthStore.createTransaction({
      provider: "github",
      journey: "link",
      tenantSlug: null,
      returnTo: "/oidc/account",
      nonce: "n",
      codeVerifier: "v",
      linkUserId: "user-1",
      linkTenantId: "tenant-1",
    });
    vi.spyOn(service as any, "exchangeAndFetchProfile").mockResolvedValue({
      subject: "42",
      email: "linked@example.com",
      emailVerified: true,
    });
    vi.mocked(prisma.$queryRaw).mockResolvedValueOnce([]);
    vi.mocked(idpPrisma.user.findFirst).mockResolvedValueOnce({
      id: "user-1",
      tenantId: "tenant-1",
      email: "owner@example.com",
      status: "ACTIVE",
    } as never);

    await expect(service.handleCallback("github", "code", state)).resolves.toMatchObject({
      kind: "session",
      returnTo: "/oidc/account",
    });
    expect(idpPrisma.userIdentity.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        provider: "github",
        subject: "42",
        userId: "user-1",
        tenantId: "tenant-1",
      }),
    });
  });

  it("does not disconnect the only sign-in method of a passwordless account", async () => {
    const { idpPrisma } = await import("@kannan19302/database");
    vi.mocked(idpPrisma.userSession.findUnique).mockResolvedValueOnce({
      id: "session-1",
      userId: "user-1",
      tenantId: "tenant-1",
      isActive: true,
      startedAt: new Date(),
    } as never);
    vi.mocked(idpPrisma.user.findFirst).mockResolvedValueOnce({
      id: "user-1",
      tenantId: "tenant-1",
      passwordHash: null,
    } as never);
    vi.mocked(idpPrisma.userIdentity.findMany).mockResolvedValueOnce([
      { provider: "google" },
    ] as never);

    await expect(
      service.unlinkProvider("google", "user-1", "tenant-1", "session-1"),
    ).rejects.toThrow("another sign-in method");
  });

  it("cryptographically verifies Google issuer, audience, signature and nonce", async () => {
    const { publicKey, privateKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    Object.assign(jwk, { kid: "google-test", alg: "RS256", use: "sig" });
    vi.spyOn(service as any, "keySetFor").mockReturnValue(
      createLocalJWKSet({ keys: [jwk] }),
    );
    const token = await new SignJWT({
      sub: "google-subject",
      email: "owner@example.com",
      email_verified: true,
      nonce: "expected-nonce",
    })
      .setProtectedHeader({ alg: "RS256", kid: "google-test" })
      .setIssuer("https://accounts.google.com")
      .setAudience("cid")
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(privateKey);

    await expect(
      (service as any).verifyOidcToken(
        "google",
        token,
        {
          clientId: "cid",
          jwksUrl: "https://www.googleapis.com/oauth2/v3/certs",
        },
        "expected-nonce",
      ),
    ).resolves.toMatchObject({ sub: "google-subject" });

    await expect(
      (service as any).verifyOidcToken(
        "google",
        token,
        {
          clientId: "wrong-audience",
          jwksUrl: "https://www.googleapis.com/oauth2/v3/certs",
        },
        "expected-nonce",
      ),
    ).rejects.toThrow("could not be verified");
  });

  it("verifies Microsoft tenant identity and binds the stable subject to that tenant", async () => {
    process.env.MICROSOFT_OAUTH_CLIENT_ID = "microsoft-client";
    process.env.MICROSOFT_OAUTH_CLIENT_SECRET = "secret";
    process.env.MICROSOFT_OAUTH_TENANT = "common";
    const tenantId = "11111111-2222-3333-4444-555555555555";
    const { publicKey, privateKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    Object.assign(jwk, { kid: "microsoft-test", alg: "RS256", use: "sig" });
    vi.spyOn(service as any, "keySetFor").mockReturnValue(
      createLocalJWKSet({ keys: [jwk] }),
    );
    const token = await new SignJWT({
      tid: tenantId,
      oid: "object-123",
      preferred_username: "owner@example.com",
      name: "Microsoft Owner",
      nonce: "microsoft-nonce",
    })
      .setProtectedHeader({ alg: "RS256", kid: "microsoft-test" })
      .setIssuer(`https://login.microsoftonline.com/${tenantId}/v2.0`)
      .setAudience("microsoft-client")
      .setSubject("pairwise-subject")
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(privateKey);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ id_token: token }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      ),
    );

    await expect(
      (service as any).exchangeAndFetchProfile(
        "microsoft",
        "code",
        "microsoft-nonce",
        "verifier",
      ),
    ).resolves.toMatchObject({
      subject: `${tenantId}:object-123`,
      email: "owner@example.com",
      emailVerified: true,
    });
  });

  it("accepts only a verified GitHub email", async () => {
    process.env.GITHUB_OAUTH_CLIENT_ID = "github-client";
    process.env.GITHUB_OAUTH_CLIENT_SECRET = "secret";
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ access_token: "github-token" }), {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
        )
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({ id: 42, name: "GitHub Owner", login: "owner" }),
            { status: 200, headers: { "content-type": "application/json" } },
          ),
        )
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify([
              {
                email: "owner@example.com",
                primary: true,
                verified: true,
              },
            ]),
            { status: 200, headers: { "content-type": "application/json" } },
          ),
        ),
    );

    await expect(
      (service as any).exchangeAndFetchProfile(
        "github",
        "code",
        "unused-nonce",
        "verifier",
      ),
    ).resolves.toMatchObject({
      subject: "42",
      email: "owner@example.com",
      emailVerified: true,
    });
  });

  it("creates a resumable registration ticket for a new provider identity", async () => {
    const state = await externalAuthStore.createTransaction({
      provider: "github",
      journey: "register",
      tenantSlug: null,
      returnTo: "/oidc/authorize?client_id=hub",
      nonce: "n",
      codeVerifier: "v",
    });
    vi.spyOn(service as any, "exchangeAndFetchProfile").mockResolvedValue({
      subject: "42",
      email: "new@example.com",
      emailVerified: true,
      firstName: "New",
      lastName: "Owner",
    });
    vi.mocked(prisma.$queryRaw).mockResolvedValueOnce([]).mockResolvedValueOnce([]);

    const result = await service.handleCallback("github", "code", state);
    expect(result).toMatchObject({ kind: "registration" });
    if (result.kind !== "registration") throw new Error("expected registration");
    await expect(
      service.getRegistrationProfile(result.registrationTicket),
    ).resolves.toMatchObject({
      provider: "github",
      subject: "42",
      email: "new@example.com",
    });
  });

  it("refuses automatic email-only linking to an existing account", async () => {
    const state = await externalAuthStore.createTransaction({
      provider: "google",
      journey: "login",
      tenantSlug: null,
      returnTo: "/",
      nonce: "n",
      codeVerifier: "v",
    });
    vi.spyOn(service as any, "exchangeAndFetchProfile").mockResolvedValue({
      subject: "not-linked",
      email: "existing@example.com",
      emailVerified: true,
    });
    vi.mocked(prisma.$queryRaw)
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([{ id: "existing-user" }]);

    await expect(service.handleCallback("google", "code", state)).rejects.toThrow(
      "connect this provider in Account Center",
    );
  });
});
