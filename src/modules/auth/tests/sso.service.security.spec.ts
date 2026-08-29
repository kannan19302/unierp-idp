import { beforeEach, describe, expect, it, vi } from "vitest";
import { UnauthorizedException } from "@nestjs/common";
import { SsoService } from "../sso.service";

const mocks = vi.hoisted(() => ({
  jwtVerify: vi.fn(),
  createRemoteJWKSet: vi.fn(() => "remote-jwks"),
  consumeFederationTransaction: vi.fn(),
  createFederationTransaction: vi.fn(),
  issueSession: vi.fn(),
}));

vi.mock("jose", () => ({
  jwtVerify: mocks.jwtVerify,
  createRemoteJWKSet: mocks.createRemoteJWKSet,
}));

vi.mock("@kannan19302/database", () => ({
  prisma: {
    tenant: { findUnique: vi.fn() },
    ssoConfig: { findUnique: vi.fn() },
  },
  idpPrisma: {
    user: { findFirst: vi.fn() },
    role: { findFirst: vi.fn() },
    userRole: { create: vi.fn() },
  },
  runWithTenantSession: vi.fn(async (_context: unknown, operation: () => unknown) => operation()),
}));

vi.mock("@kannan19302/auth", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@kannan19302/auth")>()),
  decryptConfigurationSecret: vi.fn(() => "synthetic-client-secret"),
}));

vi.mock("../sso-plan-gate", () => ({
  assertSsoFederationEnabled: vi.fn(),
}));

const { prisma, idpPrisma } = await import("@kannan19302/database");
const {
  jwtVerify,
  createRemoteJWKSet,
  consumeFederationTransaction,
  createFederationTransaction,
  issueSession,
} = mocks;

const issuer = "https://login.example.test/tenant-a";
const discovery = {
  issuer,
  authorization_endpoint: "https://login.example.test/authorize",
  token_endpoint: "https://login.example.test/token",
  jwks_uri: "https://login.example.test/keys",
  id_token_signing_alg_values_supported: ["RS256"],
};

function response(body: unknown, ok = true, status = 200): Response {
  return {
    ok,
    status,
    headers: new Headers({ "content-type": "application/json" }),
    json: vi.fn().mockResolvedValue(body),
    text: vi.fn().mockResolvedValue(JSON.stringify(body)),
  } as unknown as Response;
}

describe("SsoService inbound OIDC security", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", vi.fn());
    prisma.tenant.findUnique.mockResolvedValue({ id: "tenant-a", slug: "acme" });
    prisma.ssoConfig.findUnique.mockResolvedValue({
      isActive: true,
      verificationStatus: "VERIFIED",
      lastVerifiedAt: new Date("2026-08-29T00:00:00.000Z"),
      issuerUrl: issuer,
      clientId: "client-a",
      clientSecret: "not-a-real-secret",
    });
    idpPrisma.user.findFirst.mockResolvedValue({ id: "user-a", status: "ACTIVE" });
    issueSession.mockResolvedValue({ accessToken: "session" });
  });

  function service(): SsoService {
    return new SsoService(
      { issueSession } as never,
      { consumeFederationTransaction, createFederationTransaction } as never,
    );
  }

  it("uses an opaque one-time state with nonce and S256 PKCE", async () => {
    createFederationTransaction.mockResolvedValue("opaque-state-handle");
    vi.mocked(fetch).mockResolvedValueOnce(response(discovery));

    const url = new URL(await service().buildOidcLoginUrl("acme", "/apps"));

    expect(url.origin + url.pathname).toBe("https://login.example.test/authorize");
    expect(url.searchParams.get("state")).toBe("opaque-state-handle");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("nonce")).toMatch(/^[A-Za-z0-9_-]{32}$/);
    expect(url.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(createFederationTransaction).toHaveBeenCalledWith(expect.objectContaining({
      tenantSlug: "acme",
      returnTo: "/apps",
      nonce: url.searchParams.get("nonce"),
      codeVerifier: expect.stringMatching(/^[A-Za-z0-9_-]{64}$/),
    }));
  });

  it("rejects replayed or cross-tenant opaque state before any upstream request", async () => {
    consumeFederationTransaction.mockResolvedValue({
      tenantSlug: "other-tenant",
      returnTo: "/apps",
      nonce: "nonce",
      codeVerifier: "verifier",
    });

    await expect(service().handleOidcCallback("acme", "code", "opaque-state")).rejects.toThrow(UnauthorizedException);
    expect(fetch).not.toHaveBeenCalled();
    expect(issueSession).not.toHaveBeenCalled();
  });

  it("verifies issuer, audience, signing algorithm, age and nonce before issuing a session", async () => {
    consumeFederationTransaction.mockResolvedValue({
      tenantSlug: "acme",
      returnTo: "/apps",
      nonce: "expected-nonce",
      codeVerifier: "stored-verifier",
    });
    vi.mocked(fetch)
      .mockResolvedValueOnce(response(discovery))
      .mockResolvedValueOnce(response({ id_token: "signed.id.token" }));
    jwtVerify.mockResolvedValue({
      payload: {
        aud: "client-a",
        nonce: "expected-nonce",
        email: "person@example.test",
        email_verified: true,
      },
    });

    await expect(service().handleOidcCallback("acme", "code", "opaque-state")).resolves.toMatchObject({
      returnTo: "/apps",
    });

    expect(createRemoteJWKSet).toHaveBeenCalledWith(expect.any(URL), expect.objectContaining({ cacheMaxAge: 600000 }));
    expect(jwtVerify).toHaveBeenCalledWith("signed.id.token", "remote-jwks", expect.objectContaining({
      algorithms: ["RS256"],
      issuer,
      audience: "client-a",
      maxTokenAge: "5m",
    }));
    expect(vi.mocked(fetch).mock.calls[1]?.[1]).toMatchObject({
      method: "POST",
      body: expect.any(URLSearchParams),
    });
    expect(String((vi.mocked(fetch).mock.calls[1]?.[1] as RequestInit).body)).toContain("code_verifier=stored-verifier");
    expect(issueSession).toHaveBeenCalledOnce();
  });

  it("denies a verified-signature result whose nonce does not match the stored transaction", async () => {
    consumeFederationTransaction.mockResolvedValue({
      tenantSlug: "acme",
      returnTo: "/apps",
      nonce: "expected-nonce",
      codeVerifier: "stored-verifier",
    });
    vi.mocked(fetch)
      .mockResolvedValueOnce(response(discovery))
      .mockResolvedValueOnce(response({ id_token: "signed.id.token" }));
    jwtVerify.mockResolvedValue({
      payload: { aud: "client-a", nonce: "replayed-nonce", email: "person@example.test", email_verified: true },
    });

    await expect(service().handleOidcCallback("acme", "code", "opaque-state")).rejects.toThrow(UnauthorizedException);
    expect(issueSession).not.toHaveBeenCalled();
  });

  it("denies insecure or local endpoints in issuer metadata", async () => {
    createFederationTransaction.mockResolvedValue("opaque-state-handle");
    vi.mocked(fetch).mockResolvedValueOnce(response({
      ...discovery,
      token_endpoint: "http://127.0.0.1/admin",
    }));

    await expect(service().buildOidcLoginUrl("acme", "/apps")).rejects.toThrow(UnauthorizedException);
    expect(createFederationTransaction).not.toHaveBeenCalled();
  });
});
