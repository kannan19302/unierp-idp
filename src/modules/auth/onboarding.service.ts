import {
  Injectable,
  NotFoundException,
  BadRequestException,
} from "@nestjs/common";
import { idpPrisma, prisma } from "@unerp/database";
import {
  onboardingChecklistResponseSchema,
  type OnboardingChecklistResponse,
} from "@unerp/shared";
import {
  INDUSTRY_APP_PRIORITY,
  DEFAULT_APP_PRIORITY,
} from "../../common/app-slug-map";

export const ONBOARDING_CHECKLIST_KEYS = [
  "profile",
  "logo",
  "invite",
  "app",
  "plan",
  "dashboard",
] as const;

export type OnboardingChecklistKey = (typeof ONBOARDING_CHECKLIST_KEYS)[number];

export interface OnboardingChecklistState {
  profile: boolean;
  logo: boolean;
  invite: boolean;
  app: boolean;
  plan: boolean;
  dashboard: boolean;
}

/**
 * Industry -> preferred checklist step order. Any key omitted keeps its
 * relative position from ONBOARDING_CHECKLIST_KEYS, appended after.
 */
const INDUSTRY_CHECKLIST_ORDER: Record<string, OnboardingChecklistKey[]> = {
  healthcare: ["profile", "invite", "app", "logo", "plan", "dashboard"],
  education: ["profile", "app", "invite", "logo", "plan", "dashboard"],
  "real-estate": ["profile", "invite", "plan", "app", "logo", "dashboard"],
  manufacturing: ["profile", "app", "logo", "invite", "plan", "dashboard"],
  services: ["profile", "invite", "app", "plan", "logo", "dashboard"],
  retail: ["profile", "app", "invite", "logo", "plan", "dashboard"],
  "field-service": ["profile", "app", "invite", "logo", "plan", "dashboard"],
};

function resolveIndustryMeta(industry: string | null | undefined): {
  checklistOrder: OnboardingChecklistKey[];
  priorityAppSlugs: string[];
} {
  const key = (industry || "").toLowerCase();
  return {
    checklistOrder: INDUSTRY_CHECKLIST_ORDER[key] || [
      ...ONBOARDING_CHECKLIST_KEYS,
    ],
    priorityAppSlugs: INDUSTRY_APP_PRIORITY[key] || DEFAULT_APP_PRIORITY,
  };
}

function toResponse(
  checklist: OnboardingChecklistState,
  industry: string | null | undefined,
): OnboardingChecklistResponse {
  const { checklistOrder, priorityAppSlugs } = resolveIndustryMeta(industry);
  return onboardingChecklistResponseSchema.parse({
    ...checklist,
    checklistOrder,
    priorityAppSlugs,
  });
}

/** Steps whose completion is genuinely a one-shot "user showed up" signal
 * with no better DB proxy — persisted in tenant.settings.onboardingChecklist.
 * All other keys are derived live from real backend state (see
 * getOnboardingState) and must NOT be stored/mutated via this path. */
const MANUALLY_COMPLETABLE_KEYS: readonly OnboardingChecklistKey[] = [
  "dashboard",
];

@Injectable()
export class OnboardingService {
  /**
   * Returns the onboarding checklist state for a tenant, personalized by the
   * tenant's `industry` (checklist step order + priority app slugs).
   *
   * Five of the six steps are derived live from real backend state (not
   * trusted client clicks); only `dashboard` remains a persisted flag.
   */
  async getOnboardingState(
    tenantId: string,
    userId: string,
  ): Promise<OnboardingChecklistResponse> {
    const tenant = await prisma.tenant.findUnique({
      where: { id: tenantId },
    });

    if (!tenant) {
      throw new NotFoundException("Tenant not found");
    }

    const settings = (tenant.settings as Record<string, any>) || {};
    const industry = settings.industry as string | null | undefined;
    const dashboardDone = Boolean(
      (settings.onboardingChecklist as OnboardingChecklistState | undefined)
        ?.dashboard,
    );

    const [user, inviteCount, marketplaceAppCount, subscription] =
      await Promise.all([
        idpPrisma.user.findFirst({
          where: { id: userId, tenantId },
          select: { avatar: true },
        }),
        idpPrisma.user.count({
          where: {
            tenantId,
            id: { not: userId },
            status: { in: ["INVITED", "ACTIVE"] },
          },
        }),
        prisma.installedApp.count({
          where: { tenantId, source: "MARKETPLACE" },
        }),
        prisma.tenantSubscription.findUnique({
          where: { tenantId },
          include: { plan: true },
        }),
      ]);

    const logoUrl = settings.logoUrl;
    const planName = subscription?.plan?.name?.toLowerCase();

    const checklist: OnboardingChecklistState = {
      profile: Boolean(user?.avatar),
      logo: typeof logoUrl === "string" && logoUrl.trim().length > 0,
      invite: inviteCount > 0,
      app: marketplaceAppCount > 0,
      plan: Boolean(
        subscription && planName && planName !== "free" && planName !== "trial",
      ),
      dashboard: dashboardDone,
    };

    return toResponse(checklist, industry);
  }

  /**
   * Completes a specific step in the onboarding checklist. Only `dashboard`
   * remains manually completable — the other five keys are derived live from
   * real backend state in getOnboardingState and can no longer be faked by a
   * client click.
   */
  async completeStep(
    tenantId: string,
    userId: string,
    key: string,
  ): Promise<OnboardingChecklistResponse> {
    if (!ONBOARDING_CHECKLIST_KEYS.includes(key as any)) {
      throw new BadRequestException(`Invalid onboarding checklist key: ${key}`);
    }
    if (!MANUALLY_COMPLETABLE_KEYS.includes(key as OnboardingChecklistKey)) {
      throw new BadRequestException(
        `Onboarding checklist key "${key}" is derived from live backend state and cannot be manually completed.`,
      );
    }

    const tenant = await prisma.tenant.findUnique({
      where: { id: tenantId },
    });

    if (!tenant) {
      throw new NotFoundException("Tenant not found");
    }

    const settings = (tenant.settings as Record<string, any>) || {};
    const existing =
      (settings.onboardingChecklist as OnboardingChecklistState) || {};

    if (existing[key as OnboardingChecklistKey] !== true) {
      const updatedSettings = {
        ...settings,
        onboardingChecklist: {
          ...existing,
          [key]: true,
        },
      };

      await prisma.tenant.update({
        where: { id: tenantId },
        data: {
          settings: updatedSettings as any,
        },
      });
    }

    return this.getOnboardingState(tenantId, userId);
  }
}
