import { describe, it, expect, vi, beforeEach } from "vitest";
import { createHash, randomBytes } from "node:crypto";

vi.mock("@kannan19302/database", () => ({
  idpPrisma: {
    authorizationCode: {
      create: vi.fn(),
      findUnique: vi.fn(),
      updateMany: vi.fn(),
      deleteMany: vi.fn(),
    },
    refreshGrant: { updateMany: vi.fn() },
  },
  prisma: {},
  runWithTenantSession: vi.fn((_s: unknown, fn: () => unknown) => fn()),
}));

import { idpPrisma } from "@kannan19302/database";
import {
  AuthorizationService,
  OAuthError,
  verifyPkce,
  hashCode,
} from "../authorization.service";

const S256 = "S256";

function pkcePair() {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

function storedCode(over: Record<string, unknown> = {}) {
  const { challenge } = pkcePair();
  return {
    codeHash: "hash",
    clientId: "unierp-tenant-apps",
    userId: "u1",
    tenantId: "t1",
    sid: "sess-1",
    redirectUri: "http://localhost:4003/auth/callback",
    scopes: ["openid", "erp.read"],
    nonce: "n1",
    codeChallenge: challenge,
    codeChallengeMethod: S256,
    expiresAt: new Date(Date.now() + 60_000),
    consumedAt: null,
    ...over,
  };
}

describe("verifyPkce", () => {
  it("accepts the verifier that produced the challenge", () => {
    const { verifier, challenge } = pkcePair();
    expect(verifyPkce(verifier, challenge)).toBe(true);
  });

  it("rejects a different verifier", () => {
    const { challenge } = pkcePair();
    const other = randomBytes(32).toString("base64url");
    expect(verifyPkce(other, challenge)).toBe(false);
  });

  it("rejects empty input rather than treating it as a match", () => {
    const { verifier, challenge } = pkcePair();
    expect(verifyPkce("", challenge)).toBe(false);
    expect(verifyPkce(verifier, "")).toBe(false);
  });

  it("rejects a challenge of the wrong length without throwing", () => {
    // timingSafeEqual throws on length mismatch; that must be handled, not
    // surfaced as a 500 that tells an attacker their guess was the wrong size.
    const { verifier } = pkcePair();
    expect(() => verifyPkce(verifier, "short")).not.toThrow();
    expect(verifyPkce(verifier, "short")).toBe(false);
  });
});

describe("AuthorizationService", () => {
  let service: AuthorizationService;

  beforeEach(() => {
    vi.clearAllMocks();
    service = new AuthorizationService();
  });

  describe("issueCode", () => {
    const base = {
      clientId: "unierp-tenant-apps",
      userId: "u1",
      tenantId: "t1",
      sid: "sess-1",
      redirectUri: "http://localhost:4003/auth/callback",
      scopes: ["openid"],
      codeChallengeMethod: S256,
    };

    it("stores only a hash of the code, never the code itself", async () => {
      const { challenge } = pkcePair();
      const code = await service.issueCode({ ...base, codeChallenge: challenge });

      const written = vi.mocked(idpPrisma.authorizationCode.create).mock
        .calls[0][0] as { data: { codeHash: string } };

      expect(written.data.codeHash).toBe(hashCode(code));
      expect(written.data.codeHash).not.toBe(code);
      expect(JSON.stringify(written)).not.toContain(code);
    });

    it("refuses the plain PKCE method", async () => {
      const { challenge } = pkcePair();
      await expect(
        service.issueCode({
          ...base,
          codeChallenge: challenge,
          codeChallengeMethod: "plain",
        }),
      ).rejects.toThrow(OAuthError);
      expect(idpPrisma.authorizationCode.create).not.toHaveBeenCalled();
    });

    it("refuses to issue a code with no PKCE challenge at all", async () => {
      await expect(
        service.issueCode({ ...base, codeChallenge: "" }),
      ).rejects.toThrow(/PKCE is mandatory/);
    });

    it("issues codes that are unpredictable and distinct", async () => {
      const { challenge } = pkcePair();
      const a = await service.issueCode({ ...base, codeChallenge: challenge });
      const b = await service.issueCode({ ...base, codeChallenge: challenge });

      expect(a).not.toBe(b);
      expect(Buffer.from(a, "base64url").length).toBeGreaterThanOrEqual(32);
    });
  });

  describe("redeemCode", () => {
    const good = {
      code: "raw-code",
      clientId: "unierp-tenant-apps",
      redirectUri: "http://localhost:4003/auth/callback",
    };

    it("returns the grant for a correct redemption and consumes the code", async () => {
      const { verifier, challenge } = pkcePair();
      vi.mocked(idpPrisma.authorizationCode.findUnique).mockResolvedValue(
        storedCode({ codeChallenge: challenge }) as never,
      );
      vi.mocked(idpPrisma.authorizationCode.updateMany).mockResolvedValue({
        count: 1,
      } as never);

      const grant = await service.redeemCode({ ...good, codeVerifier: verifier });

      expect(grant).toMatchObject({ userId: "u1", tenantId: "t1", sid: "sess-1" });
      expect(idpPrisma.authorizationCode.updateMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({ consumedAt: null }),
        }),
      );
    });

    it("rejects a redemption whose verifier does not match the challenge", async () => {
      const { challenge } = pkcePair();
      vi.mocked(idpPrisma.authorizationCode.findUnique).mockResolvedValue(
        storedCode({ codeChallenge: challenge }) as never,
      );

      await expect(
        service.redeemCode({ ...good, codeVerifier: "wrong-verifier" }),
      ).rejects.toThrow(OAuthError);
      // A failed PKCE check must not consume the code.
      expect(idpPrisma.authorizationCode.updateMany).not.toHaveBeenCalled();
    });

    it("rejects redemption by a different client than the code was issued to", async () => {
      const { verifier, challenge } = pkcePair();
      vi.mocked(idpPrisma.authorizationCode.findUnique).mockResolvedValue(
        storedCode({ codeChallenge: challenge }) as never,
      );

      await expect(
        service.redeemCode({
          ...good,
          clientId: "unierp-provider-admin-os",
          codeVerifier: verifier,
        }),
      ).rejects.toThrow(OAuthError);
    });

    it("rejects a redirect_uri that differs from the one the code was issued for", async () => {
      const { verifier, challenge } = pkcePair();
      vi.mocked(idpPrisma.authorizationCode.findUnique).mockResolvedValue(
        storedCode({ codeChallenge: challenge }) as never,
      );

      await expect(
        service.redeemCode({
          ...good,
          redirectUri: "http://evil.test/callback",
          codeVerifier: verifier,
        }),
      ).rejects.toThrow(OAuthError);
    });

    it("rejects an expired code", async () => {
      const { verifier, challenge } = pkcePair();
      vi.mocked(idpPrisma.authorizationCode.findUnique).mockResolvedValue(
        storedCode({
          codeChallenge: challenge,
          expiresAt: new Date(Date.now() - 1),
        }) as never,
      );

      await expect(
        service.redeemCode({ ...good, codeVerifier: verifier }),
      ).rejects.toThrow(OAuthError);
    });

    it("rejects an unknown code", async () => {
      vi.mocked(idpPrisma.authorizationCode.findUnique).mockResolvedValue(
        null as never,
      );

      await expect(
        service.redeemCode({ ...good, codeVerifier: "v" }),
      ).rejects.toThrow(OAuthError);
    });

    it("treats replay as a compromise and revokes everything derived from the session", async () => {
      // The legitimate client already exchanged this code. A second attempt
      // means it leaked, so the tokens the real client holds may be an
      // attacker's — refusing this request alone would leave those live.
      const { verifier, challenge } = pkcePair();
      vi.mocked(idpPrisma.authorizationCode.findUnique).mockResolvedValue(
        storedCode({
          codeChallenge: challenge,
          consumedAt: new Date(),
        }) as never,
      );
      vi.mocked(idpPrisma.refreshGrant.updateMany).mockResolvedValue({
        count: 3,
      } as never);

      await expect(
        service.redeemCode({ ...good, codeVerifier: verifier }),
      ).rejects.toThrow(OAuthError);

      expect(idpPrisma.refreshGrant.updateMany).toHaveBeenCalledWith({
        where: { sid: "sess-1", revokedAt: null },
        data: { revokedAt: expect.any(Date) },
      });
    });

    it("revokes the session if two concurrent redemptions race", async () => {
      // Both requests read an unconsumed row; only one conditional update can
      // match. The loser must not simply fail quietly — a race here has the
      // same shape as a replay.
      const { verifier, challenge } = pkcePair();
      vi.mocked(idpPrisma.authorizationCode.findUnique).mockResolvedValue(
        storedCode({ codeChallenge: challenge }) as never,
      );
      vi.mocked(idpPrisma.authorizationCode.updateMany).mockResolvedValue({
        count: 0,
      } as never);
      vi.mocked(idpPrisma.refreshGrant.updateMany).mockResolvedValue({
        count: 1,
      } as never);

      await expect(
        service.redeemCode({ ...good, codeVerifier: verifier }),
      ).rejects.toThrow(OAuthError);

      expect(idpPrisma.refreshGrant.updateMany).toHaveBeenCalled();
    });

    it("reports every failure mode with the same error code", async () => {
      // Distinguishing "no such code" from "wrong client" from "already used"
      // would let an attacker probe for valid codes.
      const { verifier, challenge } = pkcePair();
      const cases = [
        null,
        storedCode({ codeChallenge: challenge, expiresAt: new Date(0) }),
        storedCode({ codeChallenge: challenge, clientId: "someone-else" }),
        storedCode({ codeChallenge: challenge, redirectUri: "http://other" }),
      ];

      for (const row of cases) {
        vi.mocked(idpPrisma.authorizationCode.findUnique).mockResolvedValue(
          row as never,
        );
        const err = await service
          .redeemCode({ ...good, codeVerifier: verifier })
          .catch((e: OAuthError) => e);

        expect((err as OAuthError).code).toBe("invalid_grant");
        expect((err as OAuthError).message).toBe("Invalid authorization code");
      }
    });
  });

  describe("purgeExpiredCodes", () => {
    it("removes expired unconsumed codes but keeps consumed ones long enough to detect replay", async () => {
      vi.mocked(idpPrisma.authorizationCode.deleteMany).mockResolvedValue({
        count: 5,
      } as never);

      await service.purgeExpiredCodes(60_000);

      const where = (
        vi.mocked(idpPrisma.authorizationCode.deleteMany).mock.calls[0][0] as {
          where: { OR: Array<Record<string, unknown>> };
        }
      ).where;

      expect(where.OR).toHaveLength(2);
      expect(where.OR[0]).toMatchObject({ consumedAt: null });
      expect(where.OR[1]).toHaveProperty("consumedAt");
    });
  });
});
