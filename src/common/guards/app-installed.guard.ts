import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  ForbiddenException,
} from "@nestjs/common";
import { Observable, from } from "rxjs";
import { switchMap } from "rxjs/operators";
import { idpPrisma, prisma } from "@unerp/database";
import { moduleSlugForSegment, isKernelSlug } from "../app-slug-map";

/**
 * Blocks access to app-specific API routes when the tenant has not installed the
 * corresponding app. Runs as a global APP_INTERCEPTOR (after all guards, so
 * request.user is populated) — see TenantWriteGuard for the rationale.
 *
 * Kernel slugs (only `saas-portal` / `app-store`, see KERNEL_SLUGS) always pass
 * through, as do any path segments not registered in GATED_MODULES (e.g. dashboard,
 * admin — those are not gated at all today, see module-tiers.ts follow-up note).
 * Studio/Builder ("builder") is registered in GATED_MODULES and is NOT kernel, so it
 * is gated like Finance/HR. Unauthenticated requests also pass through (JwtAuthGuard
 * handles rejection).
 */
@Injectable()
export class AppInstalledGuard implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const request = context.switchToHttp().getRequest();
    const user = request.user as { tenantId?: string } | undefined;
    if (!user?.tenantId) {
      return next.handle();
    }

    const path: string = request.route?.path || request.url || "";
    const segments = path.replace(/^\/+/, "").split("/");

    // Determine the first meaningful path segment after /api/v1 or similar prefix.
    // e.g. /api/v1/finance/invoices → "finance", /admin/marketplace/install/hr → "hr" is the param, not the segment
    // We look for a known gated module segment in the path
    let foundAppSegment: string | null = null;
    for (const seg of segments) {
      const candidate = moduleSlugForSegment(seg);
      if (candidate) {
        foundAppSegment = candidate;
        break;
      }
    }
    if (!foundAppSegment) {
      return next.handle();
    }

    // Kernel apps are never gated
    if (isKernelSlug(foundAppSegment)) {
      return next.handle();
    }

    return from(
      prisma.installedApp.findFirst({
        where: { tenantId: user.tenantId, appSlug: foundAppSegment },
      }),
    ).pipe(
      switchMap((installed) => {
        if (!installed) {
          throw new ForbiddenException(
            `App "${foundAppSegment}" is not installed. Install it from the App Store first.`,
          );
        }
        return next.handle();
      }),
    );
  }
}
