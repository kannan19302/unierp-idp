import { randomUUID } from "node:crypto";

/**
 * Resolve a collision-free slug by probing `exists` for sequential suffixes
 * (`base`, `base-2`, `base-3`, …), bounded by `maxAttempts`.
 *
 * The bound is a safety invariant: an unbounded `while (await exists(slug))`
 * loop depends entirely on the datastore eventually returning "not found". If
 * that never happens (a mock, a bug, or a pathological data state), the loop
 * spins forever, growing the candidate string until the process OOMs — a latent
 * DoS. After `maxAttempts` sequential tries we fall back to a random suffix that
 * is guaranteed to terminate; the DB unique constraint remains the final
 * arbiter on insert.
 *
 * @param base       Already-slugified base string.
 * @param exists     Returns true if a row with the candidate slug already exists.
 * @param maxAttempts Sequential attempts before the random-suffix fallback.
 */
export async function resolveUniqueSlug(
  base: string,
  exists: (slug: string) => Promise<boolean>,
  maxAttempts = 50,
): Promise<string> {
  for (let n = 1; n <= maxAttempts; n++) {
    const candidate = n === 1 ? base : `${base}-${n}`;
    if (!(await exists(candidate))) return candidate;
  }
  return `${base}-${randomUUID().slice(0, 8)}`;
}
