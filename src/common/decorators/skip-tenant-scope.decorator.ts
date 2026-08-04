import { SetMetadata } from "@nestjs/common";

export const SKIP_TENANT_SCOPE_KEY = "skipTenantScope";

/**
 * Opts a controller/handler out of automatic tenant-session scoping.
 * Reserved for platform-level, cross-tenant operations (e.g. SuperAdmin
 * dashboards that intentionally aggregate across all tenants). Any handler
 * marked with this decorator is responsible for its own access control.
 */
export const SkipTenantScope = () => SetMetadata(SKIP_TENANT_SCOPE_KEY, true);
