import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from "@nestjs/common";

@Injectable()
export class TenantGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const user = request.user as { tenantId?: string } | undefined;

    if (!user || !user.tenantId) {
      throw new UnauthorizedException("Tenant context not found");
    }

    request.tenantId = user.tenantId;
    return true;
  }
}
