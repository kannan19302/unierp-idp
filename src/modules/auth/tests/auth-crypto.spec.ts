import { describe, it, expect } from "vitest";
import {
  generateTotpSecret,
  verifyTotp,
  generateRecoveryCodes,
  matchRecoveryCode,
  createResetToken,
  hashResetToken,
  encryptSecret,
  decryptSecret,
} from "../auth-crypto";
import { authenticator } from "otplib";

describe("auth-crypto", () => {
  describe("TOTP", () => {
    it("generates a usable secret and verifies a live code", () => {
      const secret = generateTotpSecret();
      expect(secret.length).toBeGreaterThan(0);
      const code = authenticator.generate(secret);
      expect(verifyTotp(code, secret)).toBe(true);
    });

    it("rejects an incorrect code", () => {
      const secret = generateTotpSecret();
      expect(verifyTotp("000000", secret)).toBe(false);
    });
  });

  describe("recovery codes", () => {
    it("generates codes whose hashes verify once and only for the right code", async () => {
      const { plain, hashes } = await generateRecoveryCodes(5);
      expect(plain).toHaveLength(5);
      expect(hashes).toHaveLength(5);

      const idx = await matchRecoveryCode(plain[2]!, hashes);
      expect(idx).toBe(2);

      const miss = await matchRecoveryCode("deadbeef-00", hashes);
      expect(miss).toBe(-1);
    }, 30000);

    it("matches case-insensitively", async () => {
      const { plain, hashes } = await generateRecoveryCodes(2);
      const idx = await matchRecoveryCode(plain[0]!.toUpperCase(), hashes);
      expect(idx).toBe(0);
    });
  });

  describe("secret encryption at rest", () => {
    it("round-trips an encrypted secret", () => {
      const secret = generateTotpSecret();
      const enc = encryptSecret(secret);
      expect(enc).toMatch(/^v1:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+$/);
      expect(enc).not.toContain(secret);
      expect(decryptSecret(enc)).toBe(secret);
    });

    it("produces a different ciphertext each time (random IV)", () => {
      expect(encryptSecret("ABCDEF")).not.toBe(encryptSecret("ABCDEF"));
    });

    it("passes legacy plaintext through unchanged", () => {
      expect(decryptSecret("LEGACYPLAINTEXTSECRET")).toBe(
        "LEGACYPLAINTEXTSECRET",
      );
    });

    it("rejects a tampered ciphertext", () => {
      const enc = encryptSecret("secret");
      const parts = enc.split(":");
      // Flip a byte in the ciphertext body — GCM auth tag must reject it.
      parts[3] = parts[3]!.replace(/.$/, (c) => (c === "0" ? "1" : "0"));
      expect(() => decryptSecret(parts.join(":"))).toThrow();
    });
  });

  describe("reset tokens", () => {
    it("produces a plaintext plus a deterministic sha256 hash", () => {
      const { plain, hash } = createResetToken();
      expect(plain).toMatch(/^[a-f0-9]{64}$/);
      expect(hash).toBe(hashResetToken(plain));
      // Different tokens hash differently.
      expect(hash).not.toBe(hashResetToken(plain + "x"));
    });
  });
});
