import { ForbiddenException } from "@nestjs/common";
import { prisma } from "@kannan19302/database";

/** The feature key gating inbound SSO federation — set on the Enterprise SaaSPlan's SaaSPlanFeature rows. */
export const SSO_FEDERATION_FEATURE_KEY = "sso.federation";

/**
 * Inbound SAML/OIDC federation is an Enterprise-plan feature (the revenue
 * model sells it as one), gated the same way W2 gates platform access via
 * `PlatformGrant` — except this is a feature *within* platforms a tenant
 * already has, not platform access itself, so it reads `SaaSPlanFeature`
 * (a boolean per-plan feature flag) rather than `PlatformGrant`.
 *
 * Throws rather than returning a boolean: every caller needs to refuse the
 * request the same way, and a caller that forgets to check a boolean return
 * value is exactly how an entitlement check silently stops mattering.
 */
export async function assertSsoFederationEnabled(tenantId: string): Promise<void> {
  const subscription = await prisma.tenantSubscription.findUnique({
    where: { tenantId },
    select: { planId: true, status: true },
  });
  if (!subscription || !["ACTIVE", "TRIAL"].includes(subscription.status)) {
    throw new ForbiddenException(
      "SSO federation requires an active Enterprise subscription.",
    );
  }

  const feature = await prisma.saaSPlanFeature.findFirst({
    where: {
      planId: subscription.planId,
      featureKey: SSO_FEDERATION_FEATURE_KEY,
      isActive: true,
    },
    select: { id: true },
  });
  if (!feature) {
    throw new ForbiddenException(
      "SSO federation is an Enterprise plan feature. Upgrade your plan to enable it.",
    );
  }
}
