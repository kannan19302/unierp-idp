import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@kannan19302/auth", () => ({
  comparePassword: vi.fn(),
}));

vi.mock("@kannan19302/database", () => ({
  idpPrisma: {
    oAuthClient: { findUnique: vi.fn() },
    clientConsent: {
      findUnique: vi.fn(),
      upsert: vi.fn(),
      updateMany: vi.fn(),
    },
  },
  prisma: {},
  runWithTenantSession: vi.fn((_s: unknown, fn: () => unknown) => fn()),
}));

import { comparePassword } from "@kannan19302/auth";
import { idpPrisma } from "@kannan19302/database";
import { OidcClientService } from "../oidc-client.service";
import { OAuthError } from "../authorization.service";

function client(over: Record<string, unknown> = {}) {
  return {
    clientId: "unierp-tenant-apps",
    name: "Tenant Applications",
    clientType: "PUBLIC",
    clientSecretHash: null,
    platformCode: "P3",
    isFirstParty: true,
    ownerTenantId: null,
    redirectUris: ["http://localhost:4003/auth/callback"],
    postLogoutRedirectUris: ["http://localhost:4000/"],
    grantTypes: ["authorization_code", "refresh_token"],
    allowedScopes: ["openid", "profile", "email", "tenant", "erp.read", "erp.write"],
    status: "ACTIVE",
    ...over,
  };
}

describe("OidcClientService", () => {
  let service: OidcClientService;

  beforeEach(() => {
    vi.clearAllMocks();
    service = new OidcClientService();
  });

  describe("getActiveClient", () => {
    it("returns an active client", async () => {
      vi.mocked(idpPrisma.oAuthClient.findUnique).mockResolvedValue(
        client() as never,
      );
      await expect(
        service.getActiveClient("unierp-tenant-apps"),
      ).resolves.toMatchObject({ clientId: "unierp-tenant-apps" });
    });

    it("treats a suspended client exactly like an unknown one", async () => {
      // A pulled registration should not be distinguishable from one that was
      // never issued.
      vi.mocked(idpPrisma.oAuthClient.findUnique).mockResolvedValue(
        client({ status: "SUSPENDED" }) as never,
      );
      const suspended = await service.getActiveClient("x").catch((e) => e);

      vi.mocked(idpPrisma.oAuthClient.findUnique).mockResolvedValue(
        null as never,
      );
      const unknown = await service.getActiveClient("y").catch((e) => e);

      expect(suspended.message).toBe(unknown.message);
      expect(suspended.code).toBe(unknown.code);
    });

    it("rejects an empty client id without hitting the database", async () => {
      await expect(service.getActiveClient("")).rejects.toThrow(OAuthError);
      expect(idpPrisma.oAuthClient.findUnique).not.toHaveBeenCalled();
    });
  });

  describe("validateRedirectUri", () => {
    it("accepts an exactly registered URI", () => {
      expect(() =>
        service.validateRedirectUri(
          client() as never,
          "http://localhost:4003/auth/callback",
        ),
      ).not.toThrow();
    });

    it("rejects prefix matches, path traversal and appended query strings", () => {
      // Prefix matching is the classic OAuth redirect vulnerability: it lets a
      // registered callback be extended into an attacker-controlled path.
      const attempts = [
        "http://localhost:4003/auth/callback/../../evil",
        "http://localhost:4003/auth/callback/evil",
        "http://localhost:4003/auth/callback?next=http://evil.test",
        "http://localhost:4003/auth/callbackX",
        "http://evil.test/auth/callback",
        "https://localhost:4003/auth/callback",
        "",
      ];

      for (const uri of attempts) {
        expect(() =>
          service.validateRedirectUri(client() as never, uri),
        ).toThrow(OAuthError);
      }
    });
  });

  describe("assertGrantAllowed", () => {
    it("permits a registered grant and refuses an unregistered one", () => {
      expect(() =>
        service.assertGrantAllowed(client() as never, "authorization_code"),
      ).not.toThrow();

      expect(() =>
        service.assertGrantAllowed(client() as never, "client_credentials"),
      ).toThrow(/not permitted/);
    });
  });

  describe("authenticateClient", () => {
    it("does not require a secret from a public client", async () => {
      // A browser or mobile client cannot keep a secret; requiring one would
      // just mean shipping it to every install.
      await expect(
        service.authenticateClient(client({ clientType: "PUBLIC" }) as never),
      ).resolves.toBeUndefined();
      expect(comparePassword).not.toHaveBeenCalled();
    });

    it("verifies a confidential client's secret", async () => {
      vi.mocked(comparePassword).mockResolvedValue(true as never);
      await expect(
        service.authenticateClient(
          client({
            clientType: "CONFIDENTIAL",
            clientSecretHash: "hash",
          }) as never,
          "s3cret",
        ),
      ).resolves.toBeUndefined();
      expect(comparePassword).toHaveBeenCalledWith("s3cret", "hash");
    });

    it("rejects a confidential client presenting the wrong secret", async () => {
      vi.mocked(comparePassword).mockResolvedValue(false as never);
      await expect(
        service.authenticateClient(
          client({
            clientType: "CONFIDENTIAL",
            clientSecretHash: "hash",
          }) as never,
          "wrong",
        ),
      ).rejects.toThrow(OAuthError);
    });

    it("rejects a confidential client presenting no secret at all", async () => {
      await expect(
        service.authenticateClient(
          client({
            clientType: "CONFIDENTIAL",
            clientSecretHash: "hash",
          }) as never,
        ),
      ).rejects.toThrow(OAuthError);
    });
  });

  describe("resolveScopes", () => {
    it("returns the requested scopes when all are registered", () => {
      expect(
        service.resolveScopes(client() as never, ["openid", "erp.read"]),
      ).toEqual(["openid", "erp.read"]);
    });

    it("rejects an unregistered scope rather than silently dropping it", () => {
      // Silently narrowing would surface later as a confusing 403 on the first
      // write, far from the cause.
      expect(() =>
        service.resolveScopes(client() as never, ["openid", "marketplace.install"]),
      ).toThrow(/not permitted/);
    });

    it("defaults to openid alone rather than everything the client may request", () => {
      expect(service.resolveScopes(client() as never, [])).toEqual(["openid"]);
    });

    it("deduplicates repeated scopes", () => {
      expect(
        service.resolveScopes(client() as never, ["openid", "openid"]),
      ).toEqual(["openid"]);
    });

    it("never grants the agent scope through a normal authorization request", () => {
      // Delegated agent authority must always derive from a live human token
      // via token exchange, never be handed to an application directly.
      expect(() =>
        service.resolveScopes(
          client({ allowedScopes: ["openid", "agent"] }) as never,
          ["openid", "agent"],
        ),
      ).toThrow(/token exchange/);
    });
  });

  describe("needsConsent", () => {
    it("never prompts for a first-party platform", async () => {
      await expect(
        service.needsConsent(client() as never, "u1", "t1", ["openid"]),
      ).resolves.toBe(false);
      expect(idpPrisma.clientConsent.findUnique).not.toHaveBeenCalled();
    });

    it("prompts for a third-party client with no prior consent", async () => {
      vi.mocked(idpPrisma.clientConsent.findUnique).mockResolvedValue(
        null as never,
      );
      await expect(
        service.needsConsent(
          client({ isFirstParty: false }) as never,
          "u1",
          "t1",
          ["openid"],
        ),
      ).resolves.toBe(true);
    });

    it("prompts again when the client asks for a scope beyond what was granted", async () => {
      vi.mocked(idpPrisma.clientConsent.findUnique).mockResolvedValue({
        scopes: ["openid"],
        revokedAt: null,
      } as never);

      await expect(
        service.needsConsent(
          client({ isFirstParty: false }) as never,
          "u1",
          "t1",
          ["openid", "erp.write"],
        ),
      ).resolves.toBe(true);
    });

    it("does not prompt when the existing consent already covers the request", async () => {
      vi.mocked(idpPrisma.clientConsent.findUnique).mockResolvedValue({
        scopes: ["openid", "erp.read"],
        revokedAt: null,
      } as never);

      await expect(
        service.needsConsent(
          client({ isFirstParty: false }) as never,
          "u1",
          "t1",
          ["openid"],
        ),
      ).resolves.toBe(false);
    });

    it("prompts again after the user revoked consent", async () => {
      vi.mocked(idpPrisma.clientConsent.findUnique).mockResolvedValue({
        scopes: ["openid"],
        revokedAt: new Date(),
      } as never);

      await expect(
        service.needsConsent(
          client({ isFirstParty: false }) as never,
          "u1",
          "t1",
          ["openid"],
        ),
      ).resolves.toBe(true);
    });
  });

  describe("consent records", () => {
    it("clears a previous revocation when consent is granted again", async () => {
      await service.recordConsent({
        clientId: "c",
        userId: "u1",
        tenantId: "t1",
        scopes: ["openid"],
      });

      const call = vi.mocked(idpPrisma.clientConsent.upsert).mock
        .calls[0][0] as { update: { revokedAt: null } };
      expect(call.update.revokedAt).toBeNull();
    });

    it("revokes only consents that are not already revoked", async () => {
      await service.revokeConsent({
        clientId: "c",
        userId: "u1",
        tenantId: "t1",
      });

      expect(idpPrisma.clientConsent.updateMany).toHaveBeenCalledWith({
        where: {
          clientId: "c",
          userId: "u1",
          tenantId: "t1",
          revokedAt: null,
        },
        data: { revokedAt: expect.any(Date) },
      });
    });
  });
});
