import { Injectable } from "@nestjs/common";
import { ThrottlerGuard } from "@nestjs/throttler";

export const TENANT_PLAN_LIMITS: Record<string, Record<string, number>> = {
  free: {
    short: 5,
    medium: 30,
  },
  starter: {
    short: 20,
    medium: 200,
  },
  business: {
    short: 50,
    medium: 500,
  },
  enterprise: {
    short: 100,
    medium: 1000,
  },
};

@Injectable()
export class TenantThrottlerGuard extends ThrottlerGuard {
  async getTracker(req: Record<string, any>): Promise<string> {
    if (req.user?.tenantId) {
      if (req.user?.userId?.startsWith("apikey:")) {
        return `apikey:${req.user.tenantId}:${req.user.userId}`;
      }
      return `tenant:${req.user.tenantId}`;
    }
    return `ip:${req.ip}`;
  }

  async handleRequest(requestProps: any): Promise<boolean> {
    const { req } = this.getRequestResponse(requestProps.context);

    const tenantPlan = req.user?.plan || "free";
    const planLimits = TENANT_PLAN_LIMITS[tenantPlan];
    if (planLimits) {
      const planLimit = planLimits[requestProps.throttler.name];
      if (planLimit !== undefined) {
        requestProps = { ...requestProps, limit: planLimit };
      }
    }

    return super.handleRequest(requestProps);
  }
}
