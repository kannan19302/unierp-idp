import { describe, it, expect, vi, beforeEach } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { jwtVerify, decodeProtectedHeader, decodeJwt } from "jose";

vi.mock("@kannan19302/database", () => ({
  idpPrisma: {
    refreshGrant: {
      create: vi.fn(),
      findUnique: vi.fn(),
      updateMany: vi.fn(),
    },
    userSession: { findUnique: vi.fn(), updateMany: vi.fn() },
  },
  prisma: {},
  runWithTenantSession: vi.fn((_s: unknown, fn: () => unknown) => fn()),
}));

import { idpPrisma } from "@kannan19302/database";
import { OidcTokenService, hashToken } from "../oidc-token.service";
import { OAuthError } from "../authorization.service";

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
});
const KID = "test-kid";

function keyServiceStub() {
  return {
    getCurrentKey: vi.fn().mockResolvedValue({
      kid: KID,
      alg: "RS256" as const,
      privateKey,
    }),
  };
}

const baseClaims = {
  sub: "u1",
  sid: "sess-1",
  tenantId: "t1",
  realm: "tenant" as const,
  roles: ["tenant-admin"],
  permissions: ["finance.invoice.read"],
  scopes: ["openid", "erp.read"],
  clientId: "unierp-tenant-apps",
  platformCode: "P3",
  mfaVerified: true,
  amr: ["pwd", "totp"],
};

describe("OidcTokenService", () => {
  let service: OidcTokenService;

  beforeEach(() => {
    vi.clearAllMocks();
    process.env.OIDC_ISSUER = "http://localhost:3005";
    service = new OidcTokenService(keyServiceStub() as never);
  });

  describe("access tokens", () => {
    it("signs with RS256 and stamps the kid so verifiers can select a key", async () => {
      const token = await service.mintAccessToken(baseClaims);
      const header = decodeProtectedHeader(token);

      expect(header.alg).toBe("RS256");
      expect(header.kid).toBe(KID);
    });

    it("verifies against the public key alone — no shared secret required", async () => {
      // This is the whole point of moving off HS256: holding the public key
      // must let you verify and NOT let you mint.
      const token = await service.mintAccessToken(baseClaims);

      const { payload } = await jwtVerify(token, publicKey, {
        issuer: "http://localhost:3005",
        audience: "unierp-tenant-apps",
      });

      expect(payload.sub).toBe("u1");
      expect(payload.tenantId).toBe("t1");
    });

    it("carries the claim shape the existing guards already read", async () => {
      const token = await service.mintAccessToken(baseClaims);
      const payload = decodeJwt(token);

      // RbacGuard / ControlPlaneGuard / JwtAuthGuard depend on these names.
      expect(payload).toMatchObject({
        sid: "sess-1",
        tenantId: "t1",
        realm: "tenant",
        roles: ["tenant-admin"],
        permissions: ["finance.invoice.read"],
        mfaVerified: true,
        typ: "session",
      });
    });

    it("binds the token to a platform and an audience", async () => {
      // A token minted for the marketplace must not be replayable against the
      // provider console.
      const token = await service.mintAccessToken(baseClaims);
      const payload = decodeJwt(token);

      expect(payload.plat).toBe("P3");
      expect(payload.aud).toBe("unierp-tenant-apps");
      expect(payload.scope).toBe("openid erp.read");
    });

    it("always carries a sid, since a token without one cannot be revoked", async () => {
      const token = await service.mintAccessToken(baseClaims);
      expect(decodeJwt(token).sid).toBe("sess-1");
    });

    it("gives every token a distinct jti", async () => {
      const a = decodeJwt(await service.mintAccessToken(baseClaims));
      const b = decodeJwt(await service.mintAccessToken(baseClaims));
      expect(a.jti).not.toBe(b.jti);
    });

    it("expires within fifteen minutes", async () => {
      const payload = decodeJwt(await service.mintAccessToken(baseClaims));
      const ttl = (payload.exp as number) - (payload.iat as number);
      expect(ttl).toBe(900);
    });

    it("includes the act claim only for delegated agent tokens", async () => {
      const plain = decodeJwt(await service.mintAccessToken(baseClaims));
      expect(plain).not.toHaveProperty("act");

      const delegated = decodeJwt(
        await service.mintAccessToken({
          ...baseClaims,
          act: { agentId: "agent-7" },
        }),
      );
      expect(delegated.act).toEqual({ agentId: "agent-7" });
    });
  });

  describe("id tokens", () => {
    const idBase = {
      sub: "u1",
      clientId: "unierp-tenant-apps",
      sid: "sess-1",
      tenantId: "t1",
      email: "a@b.test",
      name: "A B",
    };

    it("releases email and profile claims only when those scopes were granted", async () => {
      const withoutScopes = decodeJwt(
        await service.mintIdToken({ ...idBase, scopes: ["openid"] }),
      );
      expect(withoutScopes).not.toHaveProperty("email");
      expect(withoutScopes).not.toHaveProperty("name");

      const withScopes = decodeJwt(
        await service.mintIdToken({
          ...idBase,
          scopes: ["openid", "email", "profile", "tenant"],
        }),
      );
      expect(withScopes.email).toBe("a@b.test");
      expect(withScopes.name).toBe("A B");
      expect(withScopes.tenantId).toBe("t1");
    });

    it("echoes the nonce so a client can reject a response it did not initiate", async () => {
      const payload = decodeJwt(
        await service.mintIdToken({
          ...idBase,
          scopes: ["openid"],
          nonce: "n-123",
        }),
      );
      expect(payload.nonce).toBe("n-123");
    });

    it("omits nonce entirely when the client did not send one", async () => {
      const payload = decodeJwt(
        await service.mintIdToken({ ...idBase, scopes: ["openid"] }),
      );
      expect(payload).not.toHaveProperty("nonce");
    });
  });

  describe("refresh tokens", () => {
    it("stores only a hash", async () => {
      const token = await service.issueRefreshToken({
        clientId: "c",
        userId: "u1",
        tenantId: "t1",
        sid: "sess-1",
        scopes: ["openid"],
      });

      const written = vi.mocked(idpPrisma.refreshGrant.create).mock
        .calls[0][0] as { data: { tokenHash: string } };

      expect(written.data.tokenHash).toBe(hashToken(token));
      expect(JSON.stringify(written)).not.toContain(token);
    });

    it("rotates: the presented token is revoked and a new one issued", async () => {
      vi.mocked(idpPrisma.refreshGrant.findUnique).mockResolvedValue({
        id: "g1",
        clientId: "c",
        userId: "u1",
        tenantId: "t1",
        sid: "sess-1",
        scopes: ["openid"],
        revokedAt: null,
        expiresAt: new Date(Date.now() + 60_000),
      } as never);
      vi.mocked(idpPrisma.userSession.findUnique).mockResolvedValue({
        isActive: true,
        expiresAt: new Date(Date.now() + 60_000),
      } as never);
      vi.mocked(idpPrisma.refreshGrant.updateMany).mockResolvedValue({
        count: 1,
      } as never);

      const result = await service.rotateRefreshToken({
        refreshToken: "old",
        clientId: "c",
      });

      expect(result.newRefreshToken).toBeTruthy();
      expect(result.newRefreshToken).not.toBe("old");
      expect(result.grant.sid).toBe("sess-1");
      // The new grant records what it was rotated from, forming the chain that
      // makes reuse detectable.
      const created = vi.mocked(idpPrisma.refreshGrant.create).mock
        .calls[0][0] as { data: { rotatedFromId: string } };
      expect(created.data.rotatedFromId).toBe("g1");
    });

    it("treats reuse of an already-rotated token as theft and kills the session", async () => {
      // Two parties now hold the same credential and there is no way to tell
      // which is legitimate. Revoking only this token would leave the
      // attacker's other tokens live.
      vi.mocked(idpPrisma.refreshGrant.findUnique).mockResolvedValue({
        id: "g1",
        clientId: "c",
        userId: "u1",
        tenantId: "t1",
        sid: "sess-1",
        scopes: [],
        revokedAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
      } as never);

      await expect(
        service.rotateRefreshToken({ refreshToken: "old", clientId: "c" }),
      ).rejects.toThrow(OAuthError);

      expect(idpPrisma.refreshGrant.updateMany).toHaveBeenCalledWith({
        where: { sid: "sess-1", revokedAt: null },
        data: { revokedAt: expect.any(Date) },
      });
      expect(idpPrisma.userSession.updateMany).toHaveBeenCalledWith({
        where: { id: "sess-1" },
        data: { isActive: false },
      });
    });

    it("refuses to refresh once the backing session is revoked", async () => {
      // Otherwise logging out would not end anything: a refresh token could
      // resurrect the session indefinitely.
      vi.mocked(idpPrisma.refreshGrant.findUnique).mockResolvedValue({
        id: "g1",
        clientId: "c",
        userId: "u1",
        tenantId: "t1",
        sid: "sess-1",
        scopes: [],
        revokedAt: null,
        expiresAt: new Date(Date.now() + 60_000),
      } as never);
      vi.mocked(idpPrisma.userSession.findUnique).mockResolvedValue({
        isActive: false,
        expiresAt: null,
      } as never);

      await expect(
        service.rotateRefreshToken({ refreshToken: "old", clientId: "c" }),
      ).rejects.toThrow(OAuthError);
    });

    it("refuses a refresh token presented by a different client", async () => {
      vi.mocked(idpPrisma.refreshGrant.findUnique).mockResolvedValue({
        id: "g1",
        clientId: "other-client",
        userId: "u1",
        tenantId: "t1",
        sid: "sess-1",
        scopes: [],
        revokedAt: null,
        expiresAt: new Date(Date.now() + 60_000),
      } as never);

      await expect(
        service.rotateRefreshToken({ refreshToken: "old", clientId: "c" }),
      ).rejects.toThrow(OAuthError);
    });

    it("refuses an expired refresh token", async () => {
      vi.mocked(idpPrisma.refreshGrant.findUnique).mockResolvedValue({
        id: "g1",
        clientId: "c",
        userId: "u1",
        tenantId: "t1",
        sid: "sess-1",
        scopes: [],
        revokedAt: null,
        expiresAt: new Date(Date.now() - 1),
      } as never);

      await expect(
        service.rotateRefreshToken({ refreshToken: "old", clientId: "c" }),
      ).rejects.toThrow(OAuthError);
    });

    it("loses a concurrent rotation race rather than issuing two tokens", async () => {
      vi.mocked(idpPrisma.refreshGrant.findUnique).mockResolvedValue({
        id: "g1",
        clientId: "c",
        userId: "u1",
        tenantId: "t1",
        sid: "sess-1",
        scopes: [],
        revokedAt: null,
        expiresAt: new Date(Date.now() + 60_000),
      } as never);
      vi.mocked(idpPrisma.userSession.findUnique).mockResolvedValue({
        isActive: true,
        expiresAt: null,
      } as never);
      vi.mocked(idpPrisma.refreshGrant.updateMany).mockResolvedValue({
        count: 0,
      } as never);

      await expect(
        service.rotateRefreshToken({ refreshToken: "old", clientId: "c" }),
      ).rejects.toThrow(OAuthError);
      expect(idpPrisma.refreshGrant.create).not.toHaveBeenCalled();
    });

    it("revokes silently for an unknown token, per RFC 7009", async () => {
      vi.mocked(idpPrisma.refreshGrant.updateMany).mockResolvedValue({
        count: 0,
      } as never);
      await expect(service.revokeRefreshToken("nope")).resolves.toBeUndefined();
    });
  });
});
