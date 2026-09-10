import { Injectable, Logger, OnModuleInit } from "@nestjs/common";
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
} from "node:crypto";
import { calculateJwkThumbprint, exportJWK, type JWK } from "jose";
import { idpPrisma } from "@kannan19302/database";
import { encryptField, decryptField } from "@kannan19302/database";

/**
 * RS256 signing keys for the authorization server.
 *
 * Why asymmetric at all: every UniERP service previously held the same
 * NEXTAUTH_SECRET and signed HS256 tokens with it. That made "can verify a
 * token" and "can mint a token" the same capability, so any service — and
 * anyone who could read the repository — could forge a token that every other
 * service accepted. A checked-in server action in the provider console did
 * exactly that. With RS256 only this service holds a private key; everyone else
 * verifies against the public JWKS and can forge nothing.
 *
 * The private key is encrypted at rest with the platform encryption key, so a
 * leaked database dump does not hand over the ability to mint tokens.
 *
 * Rotation model: exactly one key is CURRENT and signs new tokens (enforced by
 * a partial unique index, not just by this code). Rotating demotes it to
 * PREVIOUS, which still appears in the JWKS so tokens already in flight keep
 * verifying, and promotes a freshly generated key. PREVIOUS keys are retired
 * once nothing signed by them can still be valid.
 */

const KEY_STATUS = {
  CURRENT: "CURRENT",
  PREVIOUS: "PREVIOUS",
  RETIRED: "RETIRED",
} as const;

/** Modulus size. 2048 is the floor for RS256; 3072 buys margin at negligible cost here. */
const RSA_MODULUS_BITS = 3072;

export interface ActiveSigningKey {
  kid: string;
  alg: "RS256";
  privateKey: KeyObject;
}

@Injectable()
export class SigningKeyService implements OnModuleInit {
  private readonly logger = new Logger(SigningKeyService.name);

  /**
   * Private keys are cached in memory after decryption — the decrypt is not
   * free and every token mint needs the key. Keyed by kid so a rotation that
   * happens on another replica cannot serve a stale key under the same id.
   */
  private readonly privateKeyCache = new Map<string, KeyObject>();

  async onModuleInit(): Promise<void> {
    await this.ensureCurrentKey();
  }

  /**
   * Guarantees a CURRENT key exists, creating one on first boot.
   *
   * Concurrency: several replicas may start together and all find no key. The
   * partial unique index on status='CURRENT' means exactly one INSERT wins and
   * the rest raise a uniqueness error; losing that race is expected, not an
   * error condition, so the loser simply re-reads the winner's key.
   */
  async ensureCurrentKey(): Promise<ActiveSigningKey> {
    const existing = await idpPrisma.oidcSigningKey.findFirst({
      where: { status: KEY_STATUS.CURRENT },
    });
    if (existing) {
      try {
        return this.toActiveKey(existing);
      } catch (err) {
        this.logger.warn(
          `Failed to decrypt current OIDC signing key ${existing.id}: ${err instanceof Error ? err.message : String(err)}. Demoting unreadable key and generating a new one.`,
        );
        await idpPrisma.oidcSigningKey.update({
          where: { id: existing.id },
          data: { status: KEY_STATUS.RETIRED },
        });
      }
    }

    try {
      const created = await this.generateAndStore(KEY_STATUS.CURRENT);
      this.logger.log(`Generated initial OIDC signing key ${created.id}`);
      return this.toActiveKey(created);
    } catch (err) {
      // Another replica won the race. Re-read rather than failing to boot.
      const winner = await idpPrisma.oidcSigningKey.findFirst({
        where: { status: KEY_STATUS.CURRENT },
      });
      if (!winner) throw err;
      this.logger.log(
        `Another replica created the signing key first; using ${winner.id}`,
      );
      return this.toActiveKey(winner);
    }
  }

  /** The key new tokens are signed with. */
  async getCurrentKey(): Promise<ActiveSigningKey> {
    return this.ensureCurrentKey();
  }

  /**
   * The public JWKS. CURRENT and PREVIOUS keys are both published: a token
   * signed moments before a rotation must still verify, and relying parties
   * cache the JWKS.
   */
  async getPublicJwks(): Promise<{ keys: JWK[] }> {
    const rows = await idpPrisma.oidcSigningKey.findMany({
      where: { status: { in: [KEY_STATUS.CURRENT, KEY_STATUS.PREVIOUS] } },
      orderBy: { createdAt: "desc" },
    });
    return {
      keys: rows.map((row) => ({
        ...(row.publicJwk as unknown as JWK),
        kid: row.id,
        alg: row.alg,
        use: "sig",
      })),
    };
  }

  /**
   * Promotes a new key and demotes the incumbent to PREVIOUS.
   *
   * Both writes happen in one transaction. If the demotion succeeded and the
   * promotion failed, the platform would be left with no CURRENT key and could
   * not mint a single token.
   */
  async rotate(): Promise<ActiveSigningKey> {
    const { privateKeyPem, publicJwk, kid } = this.generateKeyMaterial();

    const created = await idpPrisma.$transaction(async (tx) => {
      await tx.oidcSigningKey.updateMany({
        where: { status: KEY_STATUS.CURRENT },
        data: { status: KEY_STATUS.PREVIOUS },
      });
      return tx.oidcSigningKey.create({
        data: {
          id: kid,
          alg: "RS256",
          publicJwk: publicJwk as never,
          privateKeyPemEnc: encryptField(privateKeyPem),
          status: KEY_STATUS.CURRENT,
        },
      });
    });

    this.logger.log(`Rotated OIDC signing key; new kid ${created.id}`);
    return this.toActiveKey(created);
  }

  /**
   * Retires PREVIOUS keys that can no longer have valid tokens outstanding.
   * Retired keys leave the JWKS, so anything still signed by them stops
   * verifying — which is the intent once the longest token lifetime has passed.
   */
  async retireExpiredPreviousKeys(maxTokenLifetimeMs: number): Promise<number> {
    const cutoff = new Date(Date.now() - maxTokenLifetimeMs);
    const { count } = await idpPrisma.oidcSigningKey.updateMany({
      where: { status: KEY_STATUS.PREVIOUS, createdAt: { lt: cutoff } },
      data: { status: KEY_STATUS.RETIRED, retiredAt: new Date() },
    });
    if (count > 0) this.logger.log(`Retired ${count} previous signing key(s)`);
    return count;
  }

  // ── internals ────────────────────────────────────────────────────────────

  private async generateAndStore(status: string) {
    const { privateKeyPem, publicJwk, kid } = this.generateKeyMaterial();
    return idpPrisma.oidcSigningKey.create({
      data: {
        id: kid,
        alg: "RS256",
        publicJwk: publicJwk as never,
        privateKeyPemEnc: encryptField(privateKeyPem),
        status,
      },
    });
  }

  /**
   * The `kid` is the RFC 7638 thumbprint of the public JWK rather than a random
   * id, so it is derived from the key itself: the same key can never appear
   * under two ids, and a mismatched pairing is self-evident.
   */
  private generateKeyMaterial(): {
    privateKeyPem: string;
    publicJwk: JWK;
    kid: string;
  } {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", {
      modulusLength: RSA_MODULUS_BITS,
    });

    const privateKeyPem = privateKey
      .export({ type: "pkcs8", format: "pem" })
      .toString();

    // exportJWK/calculateJwkThumbprint are async in jose; this method stays
    // synchronous by computing the thumbprint from the JWK below via the
    // synchronous crypto path instead.
    const publicJwk = publicKey.export({ format: "jwk" }) as JWK;
    const kid = rsaThumbprintSync(publicJwk);

    return { privateKeyPem, publicJwk, kid };
  }

  private toActiveKey(row: {
    id: string;
    privateKeyPemEnc: string;
  }): ActiveSigningKey {
    const cached = this.privateKeyCache.get(row.id);
    if (cached) return { kid: row.id, alg: "RS256", privateKey: cached };

    const privateKey = createPrivateKey(decryptField(row.privateKeyPemEnc));
    this.privateKeyCache.set(row.id, privateKey);
    return { kid: row.id, alg: "RS256", privateKey };
  }
}

/**
 * RFC 7638 JWK thumbprint for an RSA public key.
 *
 * The spec is precise about this: only the required members, in lexicographic
 * order, with no whitespace. Serialising the whole JWK — or letting key order
 * vary — produces a different digest for the same key, which would break the
 * `kid` ↔ key correspondence that relying parties depend on to pick a
 * verification key.
 */
function rsaThumbprintSync(jwk: JWK): string {
  const canonical = JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n });
  // Imported lazily to keep the crypto surface of this module explicit.
  const { createHash } = require("node:crypto") as typeof import("node:crypto");
  return createHash("sha256").update(canonical).digest("base64url");
}

/** Re-exported so callers can assert against the same constants this uses. */
export { KEY_STATUS };

/**
 * Kept for parity with jose's async helpers, used by tests that want to confirm
 * our synchronous thumbprint matches the library's.
 */
export async function jwkThumbprintAsync(jwk: JWK): Promise<string> {
  return calculateJwkThumbprint(jwk, "sha256");
}

/** Exposed for tests: derive the public JWK from a PEM the way the JWKS does. */
export async function publicJwkFromPem(pem: string): Promise<JWK> {
  return exportJWK(createPublicKey(pem));
}
