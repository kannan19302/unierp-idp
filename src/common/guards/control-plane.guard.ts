import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Logger,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { CONTROL_PLANE_NAMESPACES, hasPermission } from "@unerp/shared";
import { idpPrisma, prisma, runWithTenantSession } from "@unerp/database";
import { PERMISSIONS_KEY } from "../decorators/permissions.decorator";
import { SKIP_TENANT_SCOPE_KEY } from "../decorators/skip-tenant-scope.decorator";

/**
 * The control-plane boundary, enforced in code rather than implied by a string.
 *
 * `@SkipTenantScope()` opts a handler out of tenant scoping and says, in its own
 * documentation, that such a handler "is responsible for its own access
 * control." In practice that responsibility was discharged by a single
 * `@Permissions('system.…')` decorator — and a tenant `SUPER_ADMIN` seeded with
 * `["*"]` satisfied it, which is how a customer administrator could read every
 * tenant on the platform. See docs/PLATFORM_ARCHITECTURE.md § 1.2.
 *
 * `hasPermission` now refuses to let a tenant-scoped grant satisfy a
 * control-plane permission, which closes that hole. This guard is the second,
 * independent layer: it asserts positively that the caller is a control-plane
 * principal, instead of inferring it from the absence of a denial.
 *
 * Defence in depth, deliberately: the permission fix could be regressed by a
 * future change to the matching logic, and this guard would still hold. Layer
 * three is the separate origin, realm, and ingress that Phase 1 introduces;
 * layer four is the repository split, after which tenant-plane code cannot even
 * link against control-plane handlers.
 */
@Injectable()
export class ControlPlaneGuard implements CanActivate {
  private readonly logger = new Logger(ControlPlaneGuard.name);

  constructor(private readonly reflector: Reflector) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isCrossTenant = this.reflector.getAllAndOverride<boolean>(
      SKIP_TENANT_SCOPE_KEY,
      [context.getHandler(), context.getClass()],
    );
    if (!isCrossTenant) return true;

    const required =
      this.reflector.getAllAndOverride<string[]>(PERMISSIONS_KEY, [
        context.getHandler(),
        context.getClass(),
      ]) ?? [];

    // A cross-tenant handler with no declared permission has no access control
    // at all. Fail closed and say why, rather than serving platform-wide data.
    if (required.length === 0) {
      throw new ForbiddenException(
        "Cross-tenant handler declares no permissions; refusing to serve platform-scoped data.",
      );
    }

    // Every permission guarding a cross-tenant handler must live in a
    // control-plane namespace. A tenant-scoped code here would mean tenant
    // authority is being used to authorise a platform-wide read.
    const misScoped = required.filter(
      (code) =>
        !CONTROL_PLANE_NAMESPACES.some(
          (ns) => code === ns || code.startsWith(`${ns}.`),
        ),
    );
    if (misScoped.length > 0) {
      throw new ForbiddenException(
        `Cross-tenant handler is guarded by tenant-scoped permission(s): ${misScoped.join(", ")}. ` +
          `Control-plane handlers require a ${CONTROL_PLANE_NAMESPACES.join("/")}-scoped permission.`,
      );
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user;
    if (!user) throw new ForbiddenException("User session not found");

    const userPermissions = await this.loadPermissions(user);
    const authorized = required.every((code) =>
      hasPermission(userPermissions, code),
    );

    // Control-plane access is rare, high-privilege, and worth an audit trail on
    // both outcomes — a denial here is a probe worth seeing.
    this.logger.log(
      JSON.stringify({
        event: "control_plane_access",
        outcome: authorized ? "granted" : "denied",
        userId: user.userId ?? user.sub ?? null,
        tenantId: user.tenantId ?? null,
        required,
        path: request.url,
      }),
    );

    if (!authorized) {
      throw new ForbiddenException(
        "Control-plane access requires an explicitly granted platform permission.",
      );
    }
    return true;
  }

  private async loadPermissions(user: {
    tenantId?: string;
    userId?: string;
    sub?: string;
  }): Promise<string[]> {
    const userRoles = await runWithTenantSession(
      { tenantId: user.tenantId ?? "", userId: user.userId ?? user.sub ?? "" },
      () =>
        idpPrisma.userRole.findMany({
          where: { userId: user.userId },
          include: { role: true },
        }),
    );

    const permissions: string[] = [];
    for (const ur of userRoles) {
      try {
        const parsed = JSON.parse(ur.role.permissions as string);
        if (Array.isArray(parsed)) permissions.push(...parsed);
      } catch {
        // A malformed role grants nothing. Fail closed.
      }
    }
    return permissions;
  }
}
