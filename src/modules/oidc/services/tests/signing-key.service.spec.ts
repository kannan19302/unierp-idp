import { describe, it, expect, vi, beforeEach } from "vitest";
import { generateKeyPairSync, createPublicKey } from "node:crypto";
import { calculateJwkThumbprint, exportJWK, type JWK } from "jose";

// The encryption helpers are exercised for real elsewhere; here they are
// reduced to a reversible marker so a failure points at key handling rather
// than at AES.
vi.mock("@kannan19302/database", () => {
  const store = {
    oidcSigningKey: {
      findFirst: vi.fn(),
      findMany: vi.fn(),
      create: vi.fn(),
      updateMany: vi.fn(),
    },
    $transaction: vi.fn(),
  };
  return {
    idpPrisma: store,
    prisma: {},
    runWithTenantSession: vi.fn((_s: unknown, fn: () => unknown) => fn()),
    encryptField: vi.fn((s: string) => `enc:${s}`),
    decryptField: vi.fn((s: string) => s.replace(/^enc:/, "")),
  };
});

import { idpPrisma } from "@kannan19302/database";
import {
  SigningKeyService,
  KEY_STATUS,
  jwkThumbprintAsync,
} from "../signing-key.service";

function realKeyRow(status = KEY_STATUS.CURRENT) {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  return {
    id: "test-kid",
    alg: "RS256",
    publicJwk: publicKey.export({ format: "jwk" }),
    privateKeyPemEnc: `enc:${pem}`,
    status,
    createdAt: new Date(),
    retiredAt: null,
  };
}

describe("SigningKeyService", () => {
  let service: SigningKeyService;

  beforeEach(() => {
    vi.clearAllMocks();
    service = new SigningKeyService();
  });

  describe("key id derivation", () => {
    it("derives a kid that matches the RFC 7638 thumbprint jose computes", async () => {
      // The service computes thumbprints synchronously by hand, because key
      // generation is sync. If that hand-rolled canonicalisation drifts from
      // the spec, every relying party would fail to select a verification key
      // for a token whose `kid` we published. Pin it against the reference.
      const row = await service["generateKeyMaterial"]();
      const reference = await calculateJwkThumbprint(row.publicJwk, "sha256");

      expect(row.kid).toBe(reference);
    });

    it("derives the same kid for the same key and different kids for different keys", async () => {
      const a = service["generateKeyMaterial"]();
      const b = service["generateKeyMaterial"]();

      expect(a.kid).not.toBe(b.kid);
      expect(await jwkThumbprintAsync(a.publicJwk)).toBe(a.kid);
    });

    it("produces a private key that actually pairs with the published public JWK", async () => {
      const { privateKeyPem, publicJwk } = service["generateKeyMaterial"]();
      // Deriving the public half from the private PEM must reproduce the JWK
      // we publish; a mismatch means we would advertise a key that cannot
      // verify anything we sign.
      const derived = (await exportJWK(
        createPublicKey(privateKeyPem),
      )) as JWK;

      expect(derived.n).toBe(publicJwk.n);
      expect(derived.e).toBe(publicJwk.e);
    });
  });

  describe("ensureCurrentKey", () => {
    it("returns the existing CURRENT key without generating a new one", async () => {
      vi.mocked(idpPrisma.oidcSigningKey.findFirst).mockResolvedValue(
        realKeyRow() as never,
      );

      const key = await service.ensureCurrentKey();

      expect(key.kid).toBe("test-kid");
      expect(idpPrisma.oidcSigningKey.create).not.toHaveBeenCalled();
    });

    it("generates a key on first boot when none exists", async () => {
      vi.mocked(idpPrisma.oidcSigningKey.findFirst).mockResolvedValue(
        null as never,
      );
      vi.mocked(idpPrisma.oidcSigningKey.create).mockImplementation(
        (async ({ data }: never) => data) as never,
      );

      const key = await service.ensureCurrentKey();

      expect(idpPrisma.oidcSigningKey.create).toHaveBeenCalledOnce();
      expect(key.kid).toEqual(expect.any(String));
    });

    it("recovers when another replica wins the first-boot race", async () => {
      // Several replicas boot together, all see no key, all try to insert. The
      // partial unique index lets exactly one win. Losing must not crash boot.
      const winner = realKeyRow();
      vi.mocked(idpPrisma.oidcSigningKey.findFirst)
        .mockResolvedValueOnce(null as never)
        .mockResolvedValueOnce(winner as never);
      vi.mocked(idpPrisma.oidcSigningKey.create).mockRejectedValue(
        new Error("unique constraint oidc_signing_keys_one_current"),
      );

      const key = await service.ensureCurrentKey();

      expect(key.kid).toBe(winner.id);
    });

    it("rethrows if creation fails for a reason other than losing the race", async () => {
      vi.mocked(idpPrisma.oidcSigningKey.findFirst).mockResolvedValue(
        null as never,
      );
      vi.mocked(idpPrisma.oidcSigningKey.create).mockRejectedValue(
        new Error("disk on fire"),
      );

      await expect(service.ensureCurrentKey()).rejects.toThrow("disk on fire");
    });
  });

  describe("getPublicJwks", () => {
    it("publishes CURRENT and PREVIOUS keys, so in-flight tokens still verify", async () => {
      vi.mocked(idpPrisma.oidcSigningKey.findMany).mockResolvedValue([
        realKeyRow(KEY_STATUS.CURRENT),
        { ...realKeyRow(KEY_STATUS.PREVIOUS), id: "old-kid" },
      ] as never);

      const jwks = await service.getPublicJwks();

      expect(jwks.keys).toHaveLength(2);
      expect(jwks.keys.map((k) => k.kid)).toEqual(["test-kid", "old-kid"]);
      // A JWKS entry without use/alg is ambiguous for strict verifiers.
      expect(jwks.keys.every((k) => k.use === "sig" && k.alg === "RS256")).toBe(
        true,
      );
    });

    it("never publishes private key material", async () => {
      vi.mocked(idpPrisma.oidcSigningKey.findMany).mockResolvedValue([
        realKeyRow(),
      ] as never);

      const jwks = await service.getPublicJwks();
      const serialised = JSON.stringify(jwks);

      // `d` is the RSA private exponent. Its presence would leak the key.
      expect(jwks.keys[0]).not.toHaveProperty("d");
      expect(serialised).not.toContain("PRIVATE KEY");
      expect(serialised).not.toContain("enc:");
    });

    it("excludes RETIRED keys", async () => {
      vi.mocked(idpPrisma.oidcSigningKey.findMany).mockResolvedValue(
        [] as never,
      );

      await service.getPublicJwks();

      expect(idpPrisma.oidcSigningKey.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: {
            status: { in: [KEY_STATUS.CURRENT, KEY_STATUS.PREVIOUS] },
          },
        }),
      );
    });
  });

  describe("rotate", () => {
    it("demotes and promotes inside a single transaction", async () => {
      // If the demotion committed and the promotion did not, the platform
      // would have no CURRENT key and could not mint a single token.
      const tx = {
        oidcSigningKey: {
          updateMany: vi.fn().mockResolvedValue({ count: 1 }),
          create: vi
            .fn()
            .mockImplementation(async ({ data }: never) => data),
        },
      };
      vi.mocked(idpPrisma.$transaction).mockImplementation(
        (async (fn: (t: unknown) => unknown) => fn(tx)) as never,
      );

      const key = await service.rotate();

      expect(idpPrisma.$transaction).toHaveBeenCalledOnce();
      expect(tx.oidcSigningKey.updateMany).toHaveBeenCalledWith({
        where: { status: KEY_STATUS.CURRENT },
        data: { status: KEY_STATUS.PREVIOUS },
      });
      expect(tx.oidcSigningKey.create).toHaveBeenCalledOnce();
      expect(key.kid).toEqual(expect.any(String));
    });

    it("routes the private key through encryption before persisting it", async () => {
      let captured: { privateKeyPemEnc: string } | undefined;
      const tx = {
        oidcSigningKey: {
          updateMany: vi.fn(),
          create: vi.fn().mockImplementation(async ({ data }: never) => {
            captured = data;
            return data;
          }),
        },
      };
      vi.mocked(idpPrisma.$transaction).mockImplementation(
        (async (fn: (t: unknown) => unknown) => fn(tx)) as never,
      );

      await service.rotate();

      // encryptField is faked here as a reversible marker, so the assertion
      // cannot be "the ciphertext looks nothing like the key" — under a fake
      // cipher it necessarily does. What is worth pinning is that the PEM goes
      // through the encryption path at all, and that what lands in the column
      // is the encryptor's output rather than the raw key.
      const { encryptField } = await import("@kannan19302/database");
      expect(encryptField).toHaveBeenCalledOnce();
      const encryptedInput = vi.mocked(encryptField).mock.calls[0][0];
      expect(encryptedInput).toContain("BEGIN PRIVATE KEY");

      expect(captured?.privateKeyPemEnc).toBe(`enc:${encryptedInput}`);
      expect(captured?.privateKeyPemEnc).not.toBe(encryptedInput);
    });
  });

  describe("retireExpiredPreviousKeys", () => {
    it("only retires PREVIOUS keys older than the longest token lifetime", async () => {
      vi.mocked(idpPrisma.oidcSigningKey.updateMany).mockResolvedValue({
        count: 2,
      } as never);

      const count = await service.retireExpiredPreviousKeys(3_600_000);

      expect(count).toBe(2);
      const call = vi.mocked(idpPrisma.oidcSigningKey.updateMany).mock
        .calls[0][0] as {
        where: { status: string; createdAt: { lt: Date } };
      };
      expect(call.where.status).toBe(KEY_STATUS.PREVIOUS);
      expect(call.where.createdAt.lt.getTime()).toBeLessThanOrEqual(
        Date.now() - 3_600_000 + 1000,
      );
    });
  });
});
