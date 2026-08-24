export interface PlatformNavigationConfig {
  wizardUrl: string;
  tenantAppUrl: string;
  mfaUrl: string;
  notificationPreferencesUrl: string;
  privacyCenterUrl: string;
  billingPortalUrl: string;
  supportUrl: string;
}

function destination(path: string, baseUrl: string): string {
  return new URL(path, baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`).toString();
}

/** Centralizes every cross-platform Account Center destination. */
export function getPlatformNavigationConfig(
  source: NodeJS.ProcessEnv = process.env,
): PlatformNavigationConfig {
  const wizardUrl = source.PLATFORM_WIZARD_URL ?? "http://localhost:4000";
  const tenantAppUrl = source.TENANT_APP_URL ?? "http://localhost:4003";
  return {
    wizardUrl,
    tenantAppUrl,
    mfaUrl: destination("auth/security", tenantAppUrl),
    notificationPreferencesUrl: destination("notifications/preferences", tenantAppUrl),
    privacyCenterUrl: destination("privacy", tenantAppUrl),
    billingPortalUrl: destination("saas/portal", tenantAppUrl),
    supportUrl: destination("communication/helpdesk", tenantAppUrl),
  };
}
