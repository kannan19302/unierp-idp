import { createHash, randomBytes } from "crypto";

export const API_KEY_PREFIX = "ue_live_";

/**
 * Generates a new API key. The raw key is shown to the caller exactly once;
 * only its SHA-256 hash is persisted (`hashedKey`).
 */
export function generateApiKey(): {
  raw: string;
  hashedKey: string;
  prefix: string;
} {
  const raw = `${API_KEY_PREFIX}${randomBytes(24).toString("hex")}`;
  return { raw, hashedKey: hashApiKey(raw), prefix: API_KEY_PREFIX };
}

/** Deterministic, non-reversible hash used for lookup + verification. */
export function hashApiKey(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
}
