/**
 * Module lifecycle tiers.
 *
 * The platform splits installed apps into two tiers:
 *  - **Kernel** (never uninstallable, KERNEL_SLUGS below): only `saas-portal` and
 *    `app-store`. These keep an admin surface available so a user can always
 *    re-install everything else.
 *  - **Business modules** (uninstallable): every other module, including Studio/
 *    Builder, is a normal gated module like Finance or HR. Uninstalling one is an
 *    *entitlement toggle* — the code stays resident, the data is preserved, but
 *    the module is hidden from the UI and its API is gated off until re-installed.
 *
 * Bundle-backed industry apps (healthcare, education, …) are uninstallable by their
 * own teardown path and are not listed here.
 *
 * Each gated module maps to one or more URL/route segments because a few apps are
 * mounted under a segment that differs from their app slug (e.g. Connect →
 * `communication`). The same map is used by the frontend route guard and the API
 * entitlement middleware so both agree on what "installed" means.
 */
export interface GatedModule {
  /** Canonical InstalledApp.appSlug for this module. */
  slug: string;
  /** First path segment(s) this module is served under (web routes + /api/v1/<seg>). */
  segments: string[];
}

export const GATED_MODULES: GatedModule[] = [
  { slug: "finance", segments: ["finance"] },
  { slug: "hr", segments: ["hr"] },
  { slug: "crm", segments: ["crm"] },
  { slug: "inventory", segments: ["inventory"] },
  { slug: "procurement", segments: ["procurement"] },
  { slug: "sales", segments: ["sales"] },
  { slug: "supply-chain", segments: ["supply-chain"] },
  { slug: "projects", segments: ["projects"] },
  { slug: "manufacturing", segments: ["manufacturing"] },
  { slug: "analytics", segments: ["analytics"] },
  { slug: "drive", segments: ["drive", "storage"] },
  { slug: "communication", segments: ["connect", "communication"] },
  { slug: "pos", segments: ["pos"] },
  { slug: "builder", segments: ["builder"] },
  { slug: "ecommerce", segments: ["ecommerce"] },
  { slug: "ai", segments: ["ai"] },
];

/** Set of canonical slugs that are uninstallable code-resident business modules. */
export const GATED_SLUGS = new Set(GATED_MODULES.map((m) => m.slug));

/** Map a first path segment to its gated module slug, or null if the segment isn't gated. */
export function moduleSlugForSegment(segment: string): string | null {
  const seg = (segment || "").toLowerCase();
  for (const m of GATED_MODULES) if (m.segments.includes(seg)) return m.slug;
  return null;
}

/**
 * Whether an app may be uninstalled. Bundle apps (non-core) tear themselves down;
 * code-resident core apps are only uninstallable if they're in the gated business set
 * (isCore:false / no metadata.isSystem) and not in KERNEL_SLUGS. Only `saas-portal` and
 * `app-store` are permanently locked by KERNEL_SLUGS; Studio/Builder is now a normal
 * gated business module (isCore:false) like Finance or HR. Dashboard/Admin/API-keys/SaaS
 * remain isCore:true + metadata.isSystem in the catalog and so are still locked here —
 * that isCore/isSystem semantic is a separate pre-existing inconsistency, see follow-up.
 */
export function isUninstallable(app: {
  slug: string;
  isCore?: boolean;
  metadata?: any;
}): boolean {
  // Kernel slugs are always locked regardless of how isCore/isSystem were set on the row —
  // this is a defense-in-depth belt-and-suspenders check, not a replacement for isCore/isSystem
  // (which remain authoritative for bundle-backed and future apps not in the kernel list).
  if (KERNEL_SLUGS.has(app.slug)) return false;
  if (app.isCore || app.metadata?.isSystem) return false;
  return true;
}

/**
 * Always-installed, never-uninstallable app slugs. Defined here (rather than only in
 * app-slug-map.ts) to avoid a circular import, since app-slug-map.ts re-exports from
 * this file. app-slug-map.ts re-exports this same Set — import from either.
 */
export const KERNEL_SLUGS: ReadonlySet<string> = new Set([
  "saas-portal", // NEW: merged saas + admin + api-keys + dashboard
  "app-store", // NEW: marketplace core
]);
