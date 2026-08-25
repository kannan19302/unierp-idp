import { Injectable } from "@nestjs/common";
import { idpPrisma, prisma, runWithTenantSession } from "@kannan19302/database";
import { CONTROL_PLANE_NAMESPACES } from "@kannan19302/shared";
import { OAuthError } from "./authorization.service";
import { OAUTH_ERROR } from "../oidc.constants";
import { emitAuthAudit } from "../../../common/audit/emit-auth-audit";

type Realm = "tenant" | "provider";
type Visibility = "VISIBLE_ENABLED" | "VISIBLE_DISABLED" | "HIDDEN";

export interface PlatformPrincipal {
  realm: Realm;
  roles: string[];
  permissions: string[];
  tenantId: string;
  userId?: string;
  assurance?: string;
}

export interface PlatformSummary {
  code: string;
  name: string;
  port: number;
  baseUrl: string;
  icon: string | null;
  audience: string;
  lifecycle: string;
  surfaceType: string;
  category: string;
  visibility: Exclude<Visibility, "HIDDEN">;
  launchAllowed: boolean;
  reasonCodes: string[];
  obligations: string[];
}

interface PolicyContext {
  principal: PlatformPrincipal;
  planId: string | null;
  groups: Set<string>;
  now: Date;
}

interface GrantRecord {
  platformCode: string;
  subjectType: string;
  subjectId: string;
  tenantId: string | null;
  effect: string;
  validFrom: Date | null;
  validUntil: Date | null;
  conditions: unknown;
}

interface PlatformRecord {
  code: string;
  name: string;
  port: number;
  baseUrl: string;
  icon: string | null;
  audience: string;
  requiresTenant: boolean;
  lifecycle: string;
  surfaceType: string;
  isUserFacing: boolean;
  discoverability: string;
  category: string;
  sortWeight: number;
  minimumAssurance: string | null;
}

interface Decision {
  visibility: Visibility;
  launchAllowed: boolean;
  reasonCodes: string[];
  obligations: string[];
}

/**
 * Policy decision point shared by the Wizard and /oidc/authorize.
 * The Wizard is only a view of this decision; enforcement stays at the issuer.
 */
@Injectable()
export class PlatformEntitlementService {
  // The database package and the IdP are released independently. These narrow
  // adapters describe the 1.0.15 client contract while allowing the IdP source
  // to type-check during the coordinated package rollout from 1.0.14.
  private readonly platformStore = idpPrisma.platform as unknown as {
    findMany(args: unknown): Promise<PlatformRecord[]>;
    findUnique(args: unknown): Promise<PlatformRecord | null>;
  };
  private readonly grantStore = idpPrisma.platformGrant as unknown as {
    findMany(args: unknown): Promise<GrantRecord[]>;
  };

  async listEntitledPlatforms(
    principal: PlatformPrincipal,
  ): Promise<PlatformSummary[]> {
    const platforms = await this.platformStore.findMany({
      where: { isUserFacing: true },
      orderBy: [{ sortWeight: "asc" }, { code: "asc" }],
    });
    if (platforms.length === 0) return [];

    const [grants, context] = await Promise.all([
      this.grantStore.findMany({
        where: {
          platformCode: { in: platforms.map((platform) => platform.code) },
          OR: [{ tenantId: null }, { tenantId: principal.tenantId }],
        },
      }),
      this.buildPolicyContext(principal),
    ]);

    return platforms.flatMap((platform) => {
      const decision = this.decide(
        platform,
        grants.filter((grant) => grant.platformCode === platform.code),
        context,
      );
      if (decision.visibility === "HIDDEN") return [];
      return [{
        code: platform.code,
        name: platform.name,
        port: platform.port,
        baseUrl: platform.baseUrl,
        icon: platform.icon,
        audience: platform.audience,
        lifecycle: platform.lifecycle,
        surfaceType: platform.surfaceType,
        category: platform.category,
        visibility: decision.visibility,
        launchAllowed: decision.launchAllowed,
        reasonCodes: decision.reasonCodes,
        obligations: decision.obligations,
      }];
    });
  }

  async assertMayAccess(params: PlatformPrincipal & {
    platformCode: string | null;
  }): Promise<void> {
    if (!params.platformCode) return;

    const platform = await this.platformStore.findUnique({
      where: { code: params.platformCode },
    });
    let decision: Decision = this.hidden("PLATFORM_NOT_FOUND");

    if (platform) {
      const [grants, context] = await Promise.all([
        this.grantStore.findMany({
          where: {
            platformCode: params.platformCode,
            OR: [{ tenantId: null }, { tenantId: params.tenantId }],
          },
        }),
        this.buildPolicyContext(params),
      ]);
      decision = this.decide(platform, grants, context);
    }
    const admitted = decision.launchAllowed;

    if (params.userId) {
      await emitAuthAudit({
        tenantId: params.tenantId,
        userId: params.userId,
        action: admitted ? "AUTH_PLATFORM_ENTRY" : "AUTH_PLATFORM_DENIED",
        entityType: "Platform",
        entityId: params.platformCode,
        changes: {
          realm: params.realm,
          reasonCodes: decision.reasonCodes,
          obligations: decision.obligations,
        },
      });
    }
    if (!admitted) {
      throw new OAuthError(
        OAUTH_ERROR.ACCESS_DENIED,
        "This account is not permitted to access that platform",
      );
    }
  }

  private decide(
    platform: {
      audience: string;
      lifecycle: string;
      discoverability: string;
      minimumAssurance: string | null;
      requiresTenant: boolean;
    },
    grants: GrantRecord[],
    context: PolicyContext,
  ): Decision {
    if (platform.lifecycle === "RETIRED") return this.hidden("PLATFORM_RETIRED");

    const matching = grants.filter((grant) => this.grantMatches(grant, context));
    if (matching.some((grant) => grant.effect === "DENY")) {
      return this.discoverableDenied(platform, "EXPLICIT_DENY");
    }

    const internal = platform.audience === "INTERNAL";
    const hasAuthority = internal
      ? this.holdsControlPlaneAuthority(
          context.principal.realm,
          context.principal.permissions,
        )
      : matching.some((grant) => grant.effect === "ALLOW") ||
        (platform.discoverability === "PUBLIC" && !platform.requiresTenant);

    if (!hasAuthority) {
      return this.discoverableDenied(platform, "NO_MATCHING_ENTITLEMENT");
    }
    if (platform.lifecycle === "SUSPENDED") {
      return this.visibleDisabled("PLATFORM_SUSPENDED");
    }
    if (platform.lifecycle === "MAINTENANCE") {
      return this.visibleDisabled("PLATFORM_MAINTENANCE");
    }
    if (!this.meetsAssurance(context.principal.assurance, platform.minimumAssurance)) {
      return {
        ...this.visibleDisabled("STEP_UP_REQUIRED"),
        obligations: [`step_up:${platform.minimumAssurance}`],
      };
    }

    return {
      visibility: "VISIBLE_ENABLED",
      launchAllowed: true,
      reasonCodes: [internal ? "CONTROL_PLANE_AUTHORITY" : "ENTITLEMENT_MATCH"],
      obligations: [],
    };
  }

  private grantMatches(grant: GrantRecord, context: PolicyContext): boolean {
    const { principal, now } = context;
    if (grant.tenantId !== null && grant.tenantId !== principal.tenantId) return false;
    if (grant.validFrom && grant.validFrom > now) return false;
    if (grant.validUntil && grant.validUntil <= now) return false;

    const subjectMatches =
      (grant.subjectType === "ROLE" &&
        (grant.subjectId === "*" || principal.roles.includes(grant.subjectId))) ||
      (grant.subjectType === "USER" &&
        !!principal.userId && grant.subjectId === principal.userId) ||
      (grant.subjectType === "GROUP" && context.groups.has(grant.subjectId)) ||
      (grant.subjectType === "PLAN" &&
        !!context.planId && grant.subjectId === context.planId);
    return subjectMatches && this.conditionsMatch(grant.conditions, principal);
  }

  private conditionsMatch(conditions: unknown, principal: PlatformPrincipal): boolean {
    if (!conditions || typeof conditions !== "object" || Array.isArray(conditions)) return true;
    const rule = conditions as {
      realms?: unknown;
      requiredPermissions?: unknown;
      minimumAssurance?: unknown;
    };
    if (rule.realms !== undefined) {
      if (!Array.isArray(rule.realms) || !rule.realms.includes(principal.realm)) return false;
    }
    if (rule.requiredPermissions !== undefined) {
      if (!Array.isArray(rule.requiredPermissions) ||
          !rule.requiredPermissions.every((permission) =>
            typeof permission === "string" && principal.permissions.includes(permission))) {
        return false;
      }
    }
    if (rule.minimumAssurance !== undefined) {
      if (typeof rule.minimumAssurance !== "string" ||
          !this.meetsAssurance(principal.assurance, rule.minimumAssurance)) return false;
    }
    return true;
  }

  private async buildPolicyContext(
    principal: PlatformPrincipal,
  ): Promise<PolicyContext> {
    const [subscription, memberships] = await Promise.all([
      principal.tenantId
        ? runWithTenantSession(
            { tenantId: principal.tenantId, userId: principal.userId ?? "" },
            () => prisma.tenantSubscription.findUnique({
              where: { tenantId: principal.tenantId },
              select: { planId: true, status: true },
            }),
          )
        : Promise.resolve(null),
      principal.userId
        ? idpPrisma.userGroupMember.findMany({
            where: { userId: principal.userId },
            select: { groupId: true, group: { select: { name: true } } },
          })
        : Promise.resolve([]),
    ]);

    const planId = subscription && ["ACTIVE", "TRIAL"].includes(subscription.status)
      ? subscription.planId
      : null;
    const groups = new Set<string>();
    for (const membership of memberships) {
      groups.add(membership.groupId);
      groups.add(membership.group.name);
    }
    return { principal, planId, groups, now: new Date() };
  }

  private holdsControlPlaneAuthority(realm: Realm, permissions: string[]): boolean {
    if (realm !== "provider") return false;
    return permissions.some((permission) =>
      CONTROL_PLANE_NAMESPACES.some((namespace) =>
        permission.startsWith(`${namespace}.`),
      ),
    );
  }

  private meetsAssurance(actual: string | undefined, required: string | null): boolean {
    if (!required) return true;
    const rank: Record<string, number> = { aal1: 1, aal2: 2, aal3: 3 };
    return (rank[(actual ?? "aal1").toLowerCase()] ?? 0) >=
      (rank[required.toLowerCase()] ?? Number.POSITIVE_INFINITY);
  }

  private discoverableDenied(
    platform: { discoverability: string },
    reason: string,
  ): Decision {
    return platform.discoverability === "PUBLIC"
      ? this.visibleDisabled(reason)
      : this.hidden(reason);
  }

  private hidden(reason: string): Decision {
    return { visibility: "HIDDEN", launchAllowed: false, reasonCodes: [reason], obligations: [] };
  }

  private visibleDisabled(reason: string): Decision {
    return { visibility: "VISIBLE_DISABLED", launchAllowed: false, reasonCodes: [reason], obligations: [] };
  }
}
