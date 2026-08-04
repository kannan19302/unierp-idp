import { Request, Response, NextFunction } from "express";
import { verifyToken } from "@unerp/auth";
import { idpPrisma, prisma, runWithTenantSession } from "@unerp/database";
import { moduleSlugForSegment } from "../module-tiers";

/**
 * Enforces module entitlements at the API edge: if a request targets a gated
 * business module (e.g. /api/v1/finance/...) that the tenant has *uninstalled*,
 * the route is treated as if it doesn't exist (404).
 *
 * Registered as a plain global Express middleware in main.ts (not a Nest
 * `forRoutes` middleware) so it runs reliably under Express 5 and doesn't depend
 * on the Nest exception layer — it writes the 404 response directly.
 *
 * It is deliberately fail-open for everything that isn't a gated module segment —
 * auth, admin, the App Store, kernel apps, and unmapped routes pass straight through,
 * so the blast radius is limited to the known uninstallable business modules.
 */
class EntitlementGate {
  // Tiny per-tenant install cache to avoid a DB hit on every gated request.
  private cache = new Map<string, { at: number; installed: boolean }>();
  private readonly TTL = 15_000;

  handle = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    try {
      // Strip the global prefix (/api/v1) and read the first meaningful segment.
      const segments = req.path.split("/").filter(Boolean);
      while (
        segments.length &&
        (segments[0] === "api" || /^v\d+$/.test(segments[0] as string))
      )
        segments.shift();
      const first = segments[0];
      const slug = first ? moduleSlugForSegment(first) : null;
      if (!slug) return next(); // not a gated business module — always allowed

      // Identify the tenant from the bearer token; if unauthenticated, let the
      // normal auth guard reject it (don't leak entitlement info to anonymous callers).
      const auth = req.headers.authorization;
      if (!auth || !auth.startsWith("Bearer ")) return next();
      const decoded: any = verifyToken(auth.slice(7));
      if (!decoded?.tenantId) return next();

      if (await this.isInstalled(decoded.tenantId, slug)) return next();

      res.status(404).json({
        statusCode: 404,
        error: "Not Found",
        message: `The "${slug}" module is not installed for this workspace`,
      });
    } catch {
      // Never let entitlement checking take down a request — fail open.
      next();
    }
  };

  private async isInstalled(tenantId: string, slug: string): Promise<boolean> {
    const key = `${tenantId}:${slug}`;
    const hit = this.cache.get(key);
    const now = Date.now();
    if (hit && now - hit.at < this.TTL) return hit.installed;
    // This middleware runs as a plain Express middleware ahead of Nest's
    // TenantInterceptor, so the AsyncLocalStorage tenant session it normally
    // relies on (for RLS + where-clause scoping) isn't set yet here — without
    // this wrapper, the Prisma extension skips both, current_tenant_id() is
    // unset, and the tenant_isolation RLS policy silently hides every row,
    // making every module look uninstalled. Establish the session locally.
    const row = await runWithTenantSession({ tenantId, userId: tenantId }, () =>
      prisma.installedApp.findFirst({
        where: {
          tenantId,
          OR: [{ appSlug: slug }, { appId: slug }],
          status: "ACTIVE",
        },
        select: { id: true },
      }),
    );
    const installed = !!row;
    this.cache.set(key, { at: now, installed });
    return installed;
  }
}

/** Express middleware enforcing business-module entitlements. Register via app.use(). */
export const entitlementMiddleware = new EntitlementGate().handle;
