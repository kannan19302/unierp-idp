import {
  createHash,
  randomBytes,
  timingSafeEqual,
  createCipheriv,
  createDecipheriv,
  scryptSync,
} from "node:crypto";
import { authenticator } from "otplib";
import QRCode from "qrcode";
import { hashPassword, comparePassword } from "@unerp/auth";

const TOTP_ISSUER = "UniERP";

// ── Symmetric encryption for secrets at rest (MFA TOTP seeds) ──
const ENC_PREFIX = "v1"; // ciphertext format marker: v1:<iv>:<tag>:<data> (all hex)
const ENC_ALGO = "aes-256-gcm";

/**
 * Derives a stable 32-byte key from the app secret. A dedicated
 * MFA_ENCRYPTION_KEY is preferred; otherwise we fall back to NEXTAUTH_SECRET so
 * the feature works without extra configuration. Rotating either key makes
 * existing ciphertexts undecryptable (users must re-enroll MFA), which is the
 * correct failure mode for a key rotation.
 */
function encryptionKey(): Buffer {
  const material =
    process.env.MFA_ENCRYPTION_KEY || process.env.NEXTAUTH_SECRET;
  if (!material) {
    throw new Error(
      "MFA_ENCRYPTION_KEY or NEXTAUTH_SECRET must be set to encrypt MFA secrets.",
    );
  }
  // Fixed salt: the key must be reproducible across restarts to decrypt.
  return scryptSync(material, "unerp-mfa-secret-v1", 32);
}

/**
 * Encrypts a secret for storage. Output is self-describing so {@link decryptSecret}
 * can transparently pass through legacy plaintext values.
 */
export function encryptSecret(plaintext: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv(ENC_ALGO, encryptionKey(), iv);
  const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${ENC_PREFIX}:${iv.toString("hex")}:${tag.toString("hex")}:${enc.toString("hex")}`;
}

/**
 * Decrypts a value produced by {@link encryptSecret}. Values without the version
 * prefix are assumed to be legacy plaintext (pre-encryption enrollments) and
 * returned unchanged, so the rollout needs no data migration.
 */
export function decryptSecret(stored: string): string {
  if (!stored.startsWith(`${ENC_PREFIX}:`)) {
    return stored; // legacy plaintext
  }
  const [, ivHex, tagHex, dataHex] = stored.split(":");
  const decipher = createDecipheriv(
    ENC_ALGO,
    encryptionKey(),
    Buffer.from(ivHex!, "hex"),
  );
  decipher.setAuthTag(Buffer.from(tagHex!, "hex"));
  return Buffer.concat([
    decipher.update(Buffer.from(dataHex!, "hex")),
    decipher.final(),
  ]).toString("utf8");
}

// Accept the adjacent 30s window on either side to tolerate clock skew.
authenticator.options = { window: 1 };

/**
 * Generates a fresh base32 TOTP secret usable by any standard authenticator app.
 */
export function generateTotpSecret(): string {
  return authenticator.generateSecret();
}

/**
 * Builds the otpauth:// URI and a self-contained data-URI QR image. The secret
 * is rendered locally and never leaves this process.
 */
export async function buildTotpEnrollment(email: string, secret: string) {
  const otpauthUrl = authenticator.keyuri(email, TOTP_ISSUER, secret);
  const qrDataUrl = await QRCode.toDataURL(otpauthUrl);
  return { otpauthUrl, qrDataUrl };
}

/**
 * Verifies a 6-digit TOTP code against the secret (constant-time inside otplib).
 */
export function verifyTotp(code: string, secret: string): boolean {
  try {
    return authenticator.verify({ token: code.trim(), secret });
  } catch {
    return false;
  }
}

/**
 * Generates `count` single-use recovery codes plus their bcrypt hashes. Only the
 * plaintext is ever shown to the user; only the hashes are stored.
 */
export async function generateRecoveryCodes(count = 10) {
  const plain: string[] = [];
  for (let i = 0; i < count; i++) {
    const raw = randomBytes(5).toString("hex"); // 10 hex chars
    plain.push(`${raw.slice(0, 5)}-${raw.slice(5)}`);
  }
  const hashes = await Promise.all(plain.map((c) => hashPassword(c)));
  return { plain, hashes };
}

/**
 * Checks a candidate recovery code against the stored hashes. Returns the index
 * of the consumed code, or -1 if none match.
 */
export async function matchRecoveryCode(
  candidate: string,
  hashes: string[],
): Promise<number> {
  const normalized = candidate.trim().toLowerCase();
  for (let i = 0; i < hashes.length; i++) {
    if (await comparePassword(normalized, hashes[i]!)) return i;
  }
  return -1;
}

/**
 * Generates a password-reset token: a high-entropy plaintext for the user and
 * its SHA-256 hash for storage. The plaintext is never persisted.
 */
export function createResetToken() {
  const plain = randomBytes(32).toString("hex");
  return { plain, hash: hashResetToken(plain) };
}

/**
 * SHA-256 of a reset token. Deterministic so lookups can hash-then-match; the
 * DB only ever holds the hash.
 */
export function hashResetToken(plain: string): string {
  return createHash("sha256").update(plain).digest("hex");
}

/**
 * Constant-time equality for two same-length hex digests.
 */
export function safeEqualHex(a: string, b: string): boolean {
  const ba = Buffer.from(a, "hex");
  const bb = Buffer.from(b, "hex");
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}
