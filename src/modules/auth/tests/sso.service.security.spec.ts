import { beforeEach, describe, expect, it, vi } from "vitest";
import { UnauthorizedException } from "@nestjs/common";
import { SsoService } from "../sso.service";

const mocks = vi.hoisted(() => ({
  jwtVerify: vi.fn(),
  createRemoteJWKSet: vi.fn(() => "remote-jwks"),
  consumeFederationTransaction: vi.fn(),
  createFederationTransaction: vi.fn(),
  createSamlFederationTransaction: vi.fn(),
  consumeSamlFederationTransaction: vi.fn(),
  recordSamlAssertion: vi.fn(),
  validatePostResponseAsync: vi.fn(),
  generateAuthorizeRequestAsync: vi.fn(),
  _requestToUrlAsync: vi.fn(),
  _getAdditionalParams: vi.fn(),
  issueSession: vi.fn(),
  emitAuthAudit: vi.fn(),
}));

vi.mock("jose", () => ({
  jwtVerify: mocks.jwtVerify,
  createRemoteJWKSet: mocks.createRemoteJWKSet,
}));

vi.mock("@node-saml/node-saml", () => {
  class MockSaml {
    options: any;
    constructor(options: any) {
      this.options = options;
    }
    validatePostResponseAsync = mocks.validatePostResponseAsync;
    generateAuthorizeRequestAsync = mocks.generateAuthorizeRequestAsync;
    _requestToUrlAsync = mocks._requestToUrlAsync;
    _getAdditionalParams = mocks._getAdditionalParams;
  }
  return { SAML: MockSaml };
});

vi.mock("../../../common/audit/emit-auth-audit", () => ({
  emitAuthAudit: mocks.emitAuthAudit,
}));

vi.mock("@kannan19302/database", () => ({
  prisma: {
    tenant: { findUnique: vi.fn() },
    ssoConfig: { findUnique: vi.fn() },
  },
  idpPrisma: {
    user: { findFirst: vi.fn(), create: vi.fn() },
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
  createSamlFederationTransaction,
  consumeSamlFederationTransaction,
  recordSamlAssertion,
  validatePostResponseAsync,
  generateAuthorizeRequestAsync,
  _requestToUrlAsync,
  _getAdditionalParams,
  issueSession,
  emitAuthAudit,
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
      {
        consumeFederationTransaction,
        createFederationTransaction,
        createSamlFederationTransaction,
        consumeSamlFederationTransaction,
        recordSamlAssertion,
      } as never,
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

describe("SsoService inbound SAML security", () => {
  const samlConfig = {
    id: "sso-saml-1",
    isActive: true,
    verificationStatus: "VERIFIED",
    lastVerifiedAt: new Date("2026-08-29T00:00:00.000Z"),
    samlEntryPoint: "https://idp.example.test/sso/saml",
    samlIssuer: "unierp-acme",
    samlCert: "-----BEGIN CERTIFICATE-----\nsynthetic-cert\n-----END CERTIFICATE-----",
    providerType: "SAML",
  };

  beforeEach(() => {
    vi.clearAllMocks();
    prisma.tenant.findUnique.mockResolvedValue({ id: "tenant-a", slug: "acme" });
    prisma.ssoConfig.findUnique.mockResolvedValue(samlConfig);
    idpPrisma.user.findFirst.mockResolvedValue({ id: "user-a", status: "ACTIVE", email: "saml.user@example.test" });
    issueSession.mockResolvedValue({ accessToken: "session" });
    recordSamlAssertion.mockResolvedValue(true);
  });

  function service(): SsoService {
    return new SsoService(
      { issueSession } as never,
      {
        consumeFederationTransaction,
        createFederationTransaction,
        createSamlFederationTransaction,
        consumeSamlFederationTransaction,
        recordSamlAssertion,
      } as never,
    );
  }

  it("builds a login URL with an opaque RelayState and captures AuthnRequest ID", async () => {
    generateAuthorizeRequestAsync.mockResolvedValue('<samlp:AuthnRequest ID="_req_synthetic_123" />');
    createSamlFederationTransaction.mockResolvedValue("opaque-relay-state-handle");
    _getAdditionalParams.mockReturnValue({ RelayState: "opaque-relay-state-handle" });
    _requestToUrlAsync.mockResolvedValue("https://idp.example.test/sso/saml?SAMLRequest=xyz&RelayState=opaque-relay-state-handle");

    const url = await service().buildSamlLoginUrl("acme", "/dashboard");

    expect(createSamlFederationTransaction).toHaveBeenCalledWith(expect.objectContaining({
      tenantSlug: "acme",
      returnTo: "/dashboard",
      requestId: "_req_synthetic_123",
    }));
    expect(url).toContain("RelayState=opaque-relay-state-handle");
  });

  it("accepts a valid SAML assertion matching request ID, audience, recipient and emits audit", async () => {
    consumeSamlFederationTransaction.mockResolvedValue({
      tenantSlug: "acme",
      returnTo: "/dashboard",
      requestId: "_req_synthetic_123",
      issuedAt: Date.now(),
    });

    const samlXml = `
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        InResponseTo="_req_synthetic_123"
        Destination="http://localhost:3005/api/v1/auth/sso/saml/callback/acme">
        <saml:Assertion ID="_assertion_uuid_1">
          <saml:Subject>
            <saml:SubjectConfirmationData Recipient="http://localhost:3005/api/v1/auth/sso/saml/callback/acme" />
          </saml:Subject>
          <saml:Conditions>
            <saml:AudienceRestriction>
              <saml:Audience>unierp-acme</saml:Audience>
            </saml:AudienceRestriction>
          </saml:Conditions>
        </saml:Assertion>
      </samlp:Response>
    `;
    const samlResponseBase64 = Buffer.from(samlXml).toString("base64");

    validatePostResponseAsync.mockResolvedValue({
      profile: {
        email: "saml.user@example.test",
        firstName: "Saml",
        lastName: "User",
      },
    });

    const result = await service().handleSamlCallback("acme", {
      RelayState: "opaque-relay-state-handle",
      SAMLResponse: samlResponseBase64,
    });

    expect(result.returnTo).toBe("/dashboard");
    expect(issueSession).toHaveBeenCalled();
    expect(recordSamlAssertion).toHaveBeenCalledWith("_assertion_uuid_1");
    expect(emitAuthAudit).toHaveBeenCalledWith(expect.objectContaining({
      action: "SSO_FEDERATION_LOGIN_SUCCESS",
      tenantId: "tenant-a",
      changes: expect.objectContaining({ provider: "SAML" }),
    }));
  });

  it("denies replayed SAML assertion", async () => {
    consumeSamlFederationTransaction.mockResolvedValue({
      tenantSlug: "acme",
      returnTo: "/dashboard",
      requestId: "_req_synthetic_123",
      issuedAt: Date.now(),
    });

    const samlXml = `
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        InResponseTo="_req_synthetic_123"
        Destination="http://localhost:3005/api/v1/auth/sso/saml/callback/acme">
        <saml:Assertion ID="_replayed_assertion_id">
        </saml:Assertion>
      </samlp:Response>
    `;
    const samlResponseBase64 = Buffer.from(samlXml).toString("base64");
    recordSamlAssertion.mockResolvedValue(false); // replay detected

    await expect(service().handleSamlCallback("acme", {
      RelayState: "opaque-relay-state-handle",
      SAMLResponse: samlResponseBase64,
    })).rejects.toThrow(/Replayed SAML assertion rejected/);

    expect(issueSession).not.toHaveBeenCalled();
  });

  it("denies SAML response with mismatched InResponseTo correlation", async () => {
    consumeSamlFederationTransaction.mockResolvedValue({
      tenantSlug: "acme",
      returnTo: "/dashboard",
      requestId: "_req_expected_123",
      issuedAt: Date.now(),
    });

    const samlXml = `
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        InResponseTo="_wrong_req_456">
      </samlp:Response>
    `;
    const samlResponseBase64 = Buffer.from(samlXml).toString("base64");

    await expect(service().handleSamlCallback("acme", {
      RelayState: "opaque-relay-state-handle",
      SAMLResponse: samlResponseBase64,
    })).rejects.toThrow(/SAML assertion response correlation mismatch/);

    expect(issueSession).not.toHaveBeenCalled();
  });

  it("denies SAML response with wrong recipient/destination", async () => {
    consumeSamlFederationTransaction.mockResolvedValue({
      tenantSlug: "acme",
      returnTo: "/dashboard",
      requestId: "_req_expected_123",
      issuedAt: Date.now(),
    });

    const samlXml = `
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        InResponseTo="_req_expected_123"
        Destination="https://attacker.example.com/callback">
      </samlp:Response>
    `;
    const samlResponseBase64 = Buffer.from(samlXml).toString("base64");

    await expect(service().handleSamlCallback("acme", {
      RelayState: "opaque-relay-state-handle",
      SAMLResponse: samlResponseBase64,
    })).rejects.toThrow(/SAML assertion destination mismatch/);

    expect(issueSession).not.toHaveBeenCalled();
  });

  it("denies SAML response with wrong audience", async () => {
    consumeSamlFederationTransaction.mockResolvedValue({
      tenantSlug: "acme",
      returnTo: "/dashboard",
      requestId: "_req_expected_123",
      issuedAt: Date.now(),
    });

    const samlXml = `
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        InResponseTo="_req_expected_123">
        <saml:Assertion ID="_a1">
          <saml:Audience>sp-wrong-audience</saml:Audience>
        </saml:Assertion>
      </samlp:Response>
    `;
    const samlResponseBase64 = Buffer.from(samlXml).toString("base64");

    await expect(service().handleSamlCallback("acme", {
      RelayState: "opaque-relay-state-handle",
      SAMLResponse: samlResponseBase64,
    })).rejects.toThrow(/SAML assertion audience mismatch/);

    expect(issueSession).not.toHaveBeenCalled();
  });
});

