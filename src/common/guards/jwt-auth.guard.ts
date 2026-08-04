import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from "@nestjs/common";
import { verifyTypedToken, TOKEN_TYPE } from "@unerp/auth";
import { idpPrisma, prisma, runWithTenantSession } from "@unerp/database";

const AUTH_COOKIE = "auth_token";

@Injectable()
export class JwtAuthGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();

    // 1. Prefer httpOnly cookie
    let token: string | undefined = request.cookies?.[AUTH_COOKIE];

    // 2. Fall back to Authorization header (backwards-compat during migration)
    if (!token) {
      const authHeader = request.headers.authorization;
      if (authHeader?.startsWith("Bearer ")) {
        token = authHeader.split(" ")[1];
      }
    }

    if (!token) {
      throw new UnauthorizedException("Missing authentication credentials");
    }

    // Purpose-scoped: a password-reset or MFA-challenge token carries a valid
    // signature but must never be accepted as a session.
    const decoded = verifyTypedToken<{
      sid?: string;
      tenantId?: string;
      userId?: string;
    }>(token, TOKEN_TYPE.SESSION);
    if (!decoded) {
      throw new UnauthorizedException(
        "Invalid or expired authentication token",
      );
    }

    // 3. Revocable sessions: if the token carries a session id, the session must
    // still be active and unexpired. Tokens minted before sessions were tracked
    // have no `sid` and remain valid until they expire (within a day).
    //
    // This runs before the TenantInterceptor establishes request-scoped tenant
    // context, so UserSession (RLS-protected, Track C / #21) would otherwise be
    // invisible under the unerp_api runtime role. The JWT's tenantId is already
    // signature-verified above, so it's safe to scope this one lookup by it.
    if (decoded.sid) {
      const session = decoded.tenantId
        ? await runWithTenantSession(
            { tenantId: decoded.tenantId, userId: decoded.userId ?? "" },
            () =>
              idpPrisma.userSession.findUnique({ where: { id: decoded.sid } }),
          )
        : await idpPrisma.userSession.findUnique({
            where: { id: decoded.sid },
          });
      const now = new Date();
      if (
        !session ||
        !session.isActive ||
        (session.expiresAt && session.expiresAt < now)
      ) {
        throw new UnauthorizedException("Session has been revoked or expired");
      }
    }

    request.user = decoded;
    return true;
  }
}
