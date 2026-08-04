import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("@unerp/database", () => ({
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

describe("OAuthService", () => {
  let service: OAuthService;
  const issueSession = vi.fn().mockResolvedValue({ token: "t" });

  // Minimal stand-in that reproduces the real service's DB-first/env-fallback
  // behavior against process.env, without touching the database.
  const platformCredentialsService = {
    get: vi.fn(async (provider: string) => {
      if (provider === "google-oauth") {
        return {
          clientId: process.env.GOOGLE_OAUTH_CLIENT_ID ?? "",
          clientSecret: process.env.GOOGLE_OAUTH_CLIENT_SECRET ?? "",
        };
      }
      if (provider === "microsoft-oauth") {
        return {
          clientId: process.env.MICROSOFT_OAUTH_CLIENT_ID ?? "",
          clientSecret: process.env.MICROSOFT_OAUTH_CLIENT_SECRET ?? "",
          tenantId: process.env.MICROSOFT_OAUTH_TENANT ?? "",
        };
      }
      return {};
    }),
  } as unknown as PlatformCredentialsService;

  beforeEach(() => {
    service = new OAuthService(
      { issueSession } as unknown as AuthService,
      platformCredentialsService,
    );
    delete process.env.GOOGLE_OAUTH_CLIENT_ID;
    delete process.env.GOOGLE_OAUTH_CLIENT_SECRET;
    delete process.env.MICROSOFT_OAUTH_CLIENT_ID;
    delete process.env.MICROSOFT_OAUTH_CLIENT_SECRET;
  });

  afterEach(() => {
    delete process.env.GOOGLE_OAUTH_CLIENT_ID;
    delete process.env.GOOGLE_OAUTH_CLIENT_SECRET;
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

  it("builds a Google authorization URL carrying client id and signed state", async () => {
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
    // state is a JWT (three dot-separated segments)
    expect(url.searchParams.get("state")!.split(".")).toHaveLength(3);
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
});
