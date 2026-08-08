import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { idpPrisma, prisma, runWithTenantSession } from "@kannan19302/database";
import { hasPermission } from "@kannan19302/auth";
import { PERMISSIONS_KEY } from "../decorators/permissions.decorator";

@Injectable()
export class RbacGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredPermissions = this.reflector.getAllAndOverride<string[]>(
      PERMISSIONS_KEY,
      [context.getHandler(), context.getClass()],
    );

    // If no permissions are required, allow access
    if (!requiredPermissions || requiredPermissions.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user; // Appended by JwtAuthGuard

    if (!user) {
      throw new ForbiddenException("User session not found");
    }

    // Retrieve the user's role assignments and associated roles. This guard
    // runs before the TenantInterceptor establishes request-scoped tenant
    // context, so Role (RLS-protected, Track C / #21) would otherwise be
    // invisible under the unerp_api runtime role. The JWT's tenantId was
    // already signature-verified by JwtAuthGuard, so it's safe to scope here.
    const userRoles = await runWithTenantSession(
      { tenantId: user.tenantId, userId: user.userId ?? user.sub ?? "" },
      () =>
        idpPrisma.userRole.findMany({
          where: { userId: user.userId },
          include: { role: true },
        }),
    );

    // Extract and parse permission strings from roles
    const userPermissions: string[] = [];
    for (const ur of userRoles) {
      try {
        const perms = JSON.parse(ur.role.permissions as string);
        if (Array.isArray(perms)) {
          userPermissions.push(...perms);
        }
      } catch {
        // Skip malformed role permissions
      }
    }

    // Verify if the user possesses the permissions required by the endpoint
    const isAuthorized = requiredPermissions.every((required) =>
      hasPermission(userPermissions, required),
    );

    if (!isAuthorized) {
      throw new ForbiddenException(
        "You do not have the required permissions to access this resource",
      );
    }

    return true;
  }
}
