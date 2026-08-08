import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  ForbiddenException,
} from "@nestjs/common";
import { Observable, from } from "rxjs";
import { switchMap } from "rxjs/operators";
import { idpPrisma, prisma } from "@kannan19302/database";

const WRITE_METHODS = new Set(["POST", "PUT", "DELETE", "PATCH"]);

/**
 * Blocks write operations once a tenant's 30-day free evaluation has expired
 * or its subscription is unpaid (AUTH_BILLING_PROGRAM Phase 2.3): reads stay
 * open (export/reports/billing/support), mutations return 403 until the
 * workspace is upgraded.
 *
 * This is an Interceptor, not a Guard, on purpose: it needs `request.user`,
 * which JwtAuthGuard (a per-route guard) only populates AFTER every global
 * guard has already run — NestJS executes ALL guards (global then
 * controller then route) before ANY interceptor. A global `APP_GUARD` here
 * would see `request.user` as always-undefined and silently never enforce
 * the trial/subscription check. Interceptors run once every guard (global
 * and route-level) has already completed, so `request.user` is reliably set
 * by the time this runs.
 */
@Injectable()
export class TenantWriteGuard implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const request = context.switchToHttp().getRequest();

    if (!WRITE_METHODS.has(request.method)) {
      return next.handle();
    }

    const user = request.user as { tenantId?: string } | undefined;
    if (!user?.tenantId) {
      // No authenticated tenant context — let auth guards handle it.
      return next.handle();
    }

    const path: string = request.route?.path || request.url || "";
    const pathLower = path.toLowerCase();
    const isExempt =
      pathLower.includes("/auth/") ||
      pathLower.includes("/billing") ||
      pathLower.includes("/checkout") ||
      pathLower.includes("/webhook") ||
      pathLower.includes("/saas/billing") ||
      pathLower.includes("/saas/checkout");

    if (isExempt) {
      return next.handle();
    }

    return from(this.assertWritable(user.tenantId)).pipe(
      switchMap(() => next.handle()),
    );
  }

  private async assertWritable(tenantId: string): Promise<void> {
    const tenant = await prisma.tenant.findUnique({
      where: { id: tenantId },
      include: { subscription: true },
    });
    if (!tenant) return;

    if (tenant.status !== "ACTIVE") {
      throw new ForbiddenException(
        `Your workspace status is currently ${tenant.status}. Write operations are locked.`,
      );
    }

    const subscription = tenant.subscription;

    // Tenants registered before AUTH_BILLING_PROGRAM Phase 2.3 have no
    // TenantSubscription row at all — fall back to the tenant.createdAt
    // heuristic only for those. Any tenant with an explicit subscription
    // row (every tenant registered since) is governed entirely by that
    // row's own endDate check below, which is authoritative.
    if (!subscription) {
      const trialDurationMs = 30 * 24 * 60 * 60 * 1000;
      const isTrialExpired =
        Date.now() - (tenant.createdAt ?? new Date()).getTime() >
        trialDurationMs;

      if (
        (tenant.plan === "free" || tenant.plan === "trial") &&
        isTrialExpired
      ) {
        throw new ForbiddenException({
          expired: true,
          message:
            "Your 30-day free trial has expired. Please upgrade your plan in the Billing center to resume write operations.",
        });
      }
    }

    if (subscription) {
      const isSubscriptionExpired =
        subscription.status === "EXPIRED" ||
        subscription.status === "UNPAID" ||
        (subscription.endDate && subscription.endDate < new Date());

      if (isSubscriptionExpired) {
        const message =
          subscription.status === "TRIAL"
            ? "Your 30-day free trial has ended. Please choose a plan in the Billing center to resume write operations."
            : "Your subscription has expired or is unpaid. Please update your payment details or renew your plan to resume write operations.";
        throw new ForbiddenException({ expired: true, message });
      }
    }
  }
}
