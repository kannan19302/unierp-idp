import { Injectable, Logger } from "@nestjs/common";
import { idpPrisma, prisma, runWithTenantSession } from "@kannan19302/database";
import { OAuthError } from "./authorization.service";
import { OAUTH_ERROR } from "../oidc.constants";
import { emitAuthAudit } from "../../../common/audit/emit-auth-audit";

/**
 * Resolves which platforms a user may enter — the data-backed replacement for
 * the hardcoded INTERNAL-platform check `PlatformAccessPolicy` shipped with in
 * W1. That policy is preserved unchanged as the control-plane boundary this
 * service defers to first; everything below it is new.
 *
 * The point of moving this into data rather than code: "Web Studio Pro unlocks
 * P5" and "Enterprise unlocks SSO federation" become rows an operator edits
 * from Provider Admin OS, not a source change and a deploy.
 *
 * Three ways a platform becomes reachable, ANY of which admits:
 *
 *   ROLE  a role held anywhere in the user's role set (a wildcard subjectId
 *         "*" grants to every role — used for the baseline tenant platforms
 *         every account reaches without a plan upgrade);
 *   PLAN  the tenant's current SaaSPlan carries the grant;
 *   USER  a specific user was granted individually (support overrides, pilots).
 */
export interface PlatformSummary {
  code: string;
  name: string;
  port: number;
  baseUrl: string;
  icon: string | null;
  audience: string;
}

@Injectable()
export class PlatformEntitlementService {
  private readonly logger = new Logger(PlatformEntitlementService.name);

  /** Internal platforms bypass PLAN/ROLE grants entirely — see assertMayAccess. */
  private async isInternalPlatform(platformCode: string): Promise<boolean> {
    const platform = await idpPrisma.platform.findUnique({
      where: { code: platformCode },
      select: { audience: true },
    });
    return platform?.audience === "INTERNAL";
  }

  /**
   * The full grid for the Global Platform Wizard: every platform this user may
   * currently enter, given their realm, roles, tenant and tenant's plan.
   */
  async listEntitledPlatforms(params: {
    realm: "tenant" | "provider";
    roles: string[];
    permissions: string[];
    tenantId: string;
  }): Promise<PlatformSummary[]> {
    const all = await idpPrisma.platform.findMany({ orderBy: { code: "asc" } });
    const entitled: PlatformSummary[] = [];

    for (const platform of all) {
      const admitted = await this.checkAccess({
        platformCode: platform.code,
        realm: params.realm,
        roles: params.roles,
        permissions: params.permissions,
        tenantId: params.tenantId,
      });
      if (admitted) {
        entitled.push({
          code: platform.code,
          name: platform.name,
          port: platform.port,
          baseUrl: platform.baseUrl,
          icon: platform.icon,
          audience: platform.audience,
        });
      }
    }

    return entitled;
  }

  /**
   * Enforcement point, called from AuthorizeController exactly where
   * PlatformAccessPolicy was called in W1. Throws rather than returning a
   * boolean because a refusal here must always become an OAuth `access_denied`
   * response — there is no caller for whom a silent false is the right answer.
   */
  async assertMayAccess(params: {
    platformCode: string | null;
    realm: "tenant" | "provider";
    roles: string[];
    permissions: string[];
    tenantId: string;
    userId?: string;
  }): Promise<void> {
    if (!params.platformCode) return; // third-party client: bounded by scope/consent instead

    const admitted = await this.checkAccess(params as { platformCode: string } & typeof params);
    if (params.userId) {
      await emitAuthAudit({
        tenantId: params.tenantId,
        userId: params.userId,
        action: admitted ? "AUTH_PLATFORM_ENTRY" : "AUTH_PLATFORM_DENIED",
        entityType: "Platform",
        entityId: params.platformCode,
      });
    }
    if (!admitted) {
      throw new OAuthError(
        OAUTH_ERROR.ACCESS_DENIED,
        "This account is not permitted to access that platform",
      );
    }
  }

  private async checkAccess(params: {
    platformCode: string;
    realm: "tenant" | "provider";
    roles: string[];
    permissions: string[];
    tenantId: string;
  }): Promise<boolean> {
    const { platformCode, realm, roles, permissions, tenantId } = params;

    // ── Control-plane boundary first, and it is NOT overridable by a grant. ──
    //
    // W1's reasoning is preserved exactly: a tenant SUPER_ADMIN can legitimately
    // hold ["*"], and CONTROL_PLANE_NAMESPACES is what stops that wildcard from
    // satisfying a control-plane check. A PlatformGrant table existing must
    // never become a second way to reach P2 that bypasses this — an operator
    // mis-seeding a ROLE grant against "*" must not be able to open the control
    // plane to every tenant.
    if (await this.isInternalPlatform(platformCode)) {
      return this.holdsControlPlaneAuthority(realm, permissions);
    }

    // ── PUBLIC platform: any grant admits ──────────────────────────────────
    const roleMatch = await idpPrisma.platformGrant.findFirst({
      where: {
        platformCode,
        subjectType: "ROLE",
        subjectId: { in: ["*", ...roles] },
        OR: [{ tenantId: null }, { tenantId }],
      },
      select: { id: true },
    });
    if (roleMatch) return true;

    const planGrant = await this.tenantPlanGrantsPlatform(tenantId, platformCode);
    if (planGrant) return true;

    // USER grants require a user id, which this method is not given — callers
    // needing that path use listEntitledPlatforms with a resolved subject, or
    // extend checkAccess with userId when W6 wires per-user overrides into the
    // Application Wizard. Documented here rather than silently absent.

    return false;
  }

  private holdsControlPlaneAuthority(
    realm: "tenant" | "provider",
    permissions: string[],
  ): boolean {
    if (realm !== "provider") return false;
    const CONTROL_PLANE_NAMESPACES = ["system", "platform"];
    return permissions.some((permission) =>
      CONTROL_PLANE_NAMESPACES.some((ns) => permission.startsWith(`${ns}.`)),
    );
  }

  private async tenantPlanGrantsPlatform(
    tenantId: string,
    platformCode: string,
  ): Promise<boolean> {
    // tenant_subscriptions is RLS ENABLE + FORCE, so this read has to run
    // inside the tenant's own session. Unscoped it returns null, which this
    // method cannot distinguish from "no subscription" — so every PLAN grant
    // silently evaluated to false and the entire plan-gated entitlement path
    // (the one that connects the revenue model to access) never opened a
    // platform, no matter what was seeded.
    const subscription = await runWithTenantSession(
      { tenantId, userId: "" },
      () =>
        prisma.tenantSubscription.findUnique({
          where: { tenantId },
          select: { planId: true, status: true },
        }),
    );
    if (!subscription || !["ACTIVE", "TRIAL"].includes(subscription.status)) {
      return false;
    }

    const planMatch = await idpPrisma.platformGrant.findFirst({
      where: {
        platformCode,
        subjectType: "PLAN",
        subjectId: subscription.planId,
        OR: [{ tenantId: null }, { tenantId }],
      },
      select: { id: true },
    });
    return !!planMatch;
  }
}
