/**
 * Single source of truth for "which app slug does this route belong to" and
 * "which slugs are kernel (always installed, never uninstallable)".
 *
 * This module is deliberately thin: the segment->slug table itself
 * (`GATED_MODULES`) still lives in `./module-tiers` because
 * `entitlement.middleware.ts` and `marketplace.service.ts` already import it
 * directly — duplicating the table here would reintroduce the exact
 * two-tables-that-can-drift problem this file exists to close. Everything in
 * this file is additive: the kernel-slug set, the full installable-slug list,
 * and re-exports so callers only need one import path going forward.
 */
import {
  GATED_MODULES,
  GATED_SLUGS,
  moduleSlugForSegment,
  isUninstallable,
  KERNEL_SLUGS,
  type GatedModule,
} from "./module-tiers";

// KERNEL_SLUGS is defined in module-tiers.ts (isUninstallable() needs it and app-slug-map.ts
// already depends on module-tiers.ts, so defining it there avoids a circular import) and
// re-exported here so callers only need to import from app-slug-map.ts going forward.
export { KERNEL_SLUGS };

/** The core in-house business modules (Finance, HR, …, Studio/Builder) that ship code-resident and can be toggled off. */
export const CORE_INSTALLABLE_SLUGS: readonly string[] = GATED_MODULES.map(
  (m) => m.slug,
);

/**
 * Industry/vertical bundle slugs known to the web app's route guard
 * (apps/web/app/(dashboard)/layout.tsx) that aren't part of the core 13.
 * These are provisioned via AppPackage/AppBundle install, not seeded as
 * default MarketplaceApp rows — kept here only so the slug-map endpoint can
 * report a complete picture to the frontend.
 */
export const KNOWN_INDUSTRY_APP_SLUGS: readonly string[] = [
  "education",
  "real-estate",
  "field-service",
];

/** Every slug a tenant may install/uninstall (core business modules + known industry bundles). */
export const INSTALLABLE_SLUGS: readonly string[] = [
  ...CORE_INSTALLABLE_SLUGS,
  ...KNOWN_INDUSTRY_APP_SLUGS,
];

/** True if `slug` is a kernel app (never gated, never uninstallable). */
export function isKernelSlug(slug: string): boolean {
  return KERNEL_SLUGS.has(slug);
}

/**
 * Industry -> app slugs to surface first on the Apps hub and auto-install at
 * registration. Matches `INDUSTRIES` lookup values in lookups.ts.
 * Moved here from onboarding.service.ts to be the single source of truth
 * shared with marketplace.service.ts for Phase 2 (industry-personalized install).
 */
export const INDUSTRY_APP_PRIORITY: Record<string, string[]> = {
  healthcare: ["healthcare", "hr", "inventory", "finance"],
  education: ["education", "hr", "finance", "crm"],
  "real-estate": ["real-estate", "finance", "crm", "projects"],
  manufacturing: ["manufacturing", "inventory", "procurement", "supply-chain"],
  services: ["projects", "crm", "finance", "hr"],
  retail: ["pos", "inventory", "crm", "sales"],
  "field-service": ["field-service", "projects", "inventory", "crm"],
};

/**
 * Fallback app priority when no industry is selected. Used both by the
 * Apps hub sort and the registration auto-install logic.
 */
export const DEFAULT_APP_PRIORITY: string[] = [
  "saas-portal",
  "finance",
  "crm",
  "hr",
];

/**
 * Returns the recommended app slugs for a given industry.
 * This is used for the onboarding suggestion banner/checklist (no longer
 * auto-installs — Phase 5). Returns industry-recommended core slugs only,
 * excluding kernel slugs (which are always-visible, not installable).
 */
export function getRecommendedInstallSlugs(
  industry: string | null | undefined,
): string[] {
  const priority =
    INDUSTRY_APP_PRIORITY[(industry || "").toLowerCase()] ||
    DEFAULT_APP_PRIORITY;
  const coreSet = new Set(CORE_INSTALLABLE_SLUGS);
  return priority.filter((s) => coreSet.has(s));
}

// Re-exported so callers can depend on `app-slug-map` alone going forward.
export { GATED_MODULES, GATED_SLUGS, moduleSlugForSegment, isUninstallable };
export type { GatedModule };
