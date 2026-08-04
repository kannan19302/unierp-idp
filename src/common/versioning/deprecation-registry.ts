/**
 * API deprecation registry (Foundation Roadmap Track G.1).
 *
 * The single place where API surface deprecations are declared. The
 * deprecation middleware consults this registry on every request and emits
 * RFC 9745 `Deprecation`, RFC 8594 `Sunset`, and successor `Link` headers.
 *
 * Policy: see docs/API_VERSIONING_POLICY.md — nothing is removed while a
 * paying tenant's integration depends on it inside the sunset window; every
 * entry must name a successor or a migration guide link.
 */

export interface DeprecationEntry {
  /** Path prefix AFTER the global prefix, e.g. "/api/v1/legacy-reports". */
  pathPrefix: string;
  /** When the surface became deprecated (announcement date). */
  deprecatedAt: Date;
  /** When it will stop working. Omit while "deprecated, no removal date". */
  sunsetAt?: Date;
  /** Successor URI (absolute or path) for Link rel="successor-version". */
  successor?: string;
  /** Human docs / migration guide. */
  link?: string;
}

/**
 * Live registry — currently empty: no UniERP API surface is deprecated.
 * Add entries here (never delete before their sunset passes; move expired
 * entries to the policy doc's history table).
 */
export const API_DEPRECATIONS: DeprecationEntry[] = [];

/** Longest-prefix match so nested surfaces can carry their own clocks. */
export function findDeprecation(
  path: string,
  registry: DeprecationEntry[] = API_DEPRECATIONS,
): DeprecationEntry | null {
  let best: DeprecationEntry | null = null;
  for (const entry of registry) {
    if (!path.startsWith(entry.pathPrefix)) continue;
    if (!best || entry.pathPrefix.length > best.pathPrefix.length) best = entry;
  }
  return best;
}
