import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  UnauthorizedException,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { Observable, from } from "rxjs";
import { idpPrisma, prisma, runWithTenantSession } from "@kannan19302/database";
import { SKIP_TENANT_SCOPE_KEY } from "../decorators/skip-tenant-scope.decorator";

@Injectable()
export class TenantInterceptor implements NestInterceptor {
  constructor(private readonly reflector: Reflector) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const skip = this.reflector.getAllAndOverride<boolean>(
      SKIP_TENANT_SCOPE_KEY,
      [context.getHandler(), context.getClass()],
    );
    if (skip) {
      return next.handle();
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user as
      | { tenantId: string; userId?: string; sub?: string }
      | undefined;

    if (user && user.tenantId) {
      const userId = user.userId || user.sub;
      if (!userId) {
        throw new UnauthorizedException("User ID not found in session");
      }
      return from(
        runWithTenantSession(
          {
            tenantId: user.tenantId,
            userId,
          },
          async () => {
            // Set session-level tenant context as a fallback for queries that
            // bypass the Prisma extension (e.g. raw SQL). The Prisma extension
            // also sets transaction-local set_config per query as defense-in-depth.
            // session-lifetime: set_config(..., false) scopes to session level
            // so it persists across transactions within the same connection.
            await prisma.$executeRaw`SELECT set_config('app.current_tenant_id', ${user.tenantId}, false)`;
            const { lastValueFrom } = await import("rxjs");
            return lastValueFrom(next.handle());
          },
        ),
      );
    }

    return next.handle();
  }
}
