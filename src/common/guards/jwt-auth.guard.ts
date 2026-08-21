import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from "@nestjs/common";
import { idpPrisma, prisma, runWithTenantSession } from "@kannan19302/database";
import { verifyBearerToken } from "./verify-bearer-token";

const AUTH_COOKIE = "auth_token";

/**
 * A session with no request in this window is considered idle and rejected —
 * the concurrent-session/idle-timeout half of W10. 30 minutes by default,
 * overridable per deployment; not yet per-tenant, since nothing in the
 * platform-entitlement/plan model currently carries a security-policy tier to
 * key it off.
 */
const IDLE_TIMEOUT_MS = parseInt(
  process.env.SESSION_IDLE_TIMEOUT_MS || String(30 * 60 * 1000),
  10,
);

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
    // signature but must never be accepted as a session. Accepts either the
    // legacy HS256 cookie session or an RS256 OIDC bearer access token — see
    // verify-bearer-token.ts for why both are legitimate here.
    const decoded = await verifyBearerToken(token);
    if (!decoded) {
      throw new UnauthorizedException(
        "Invalid or expired authentication token",
      );
    }

    // 3. `sid` is MANDATORY. It was previously optional, "for tokens minted
    // before sessions were tracked" — which meant any token without the claim
    // skipped revocation entirely. A checked-in server action in the provider
    // console exploited exactly that, minting `sid`-less wildcard tokens that
    // could never be revoked. A session token that cannot be revoked is not a
    // session token; reject it.
    if (!decoded.sid) {
      throw new UnauthorizedException(
        "Session token is missing a session id and cannot be revoked",
      );
    }

    // The session must still be active and unexpired.
    //
    // This runs before the TenantInterceptor establishes request-scoped tenant
    // context, so UserSession (RLS-protected, Track C / #21) would otherwise be
    // invisible under the unerp_api runtime role. The JWT's tenantId is already
    // signature-verified above, so it's safe to scope this one lookup by it.
    const session = decoded.tenantId
      ? await runWithTenantSession(
          { tenantId: decoded.tenantId, userId: decoded.userId ?? "" },
          () => idpPrisma.userSession.findUnique({ where: { id: decoded.sid } }),
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

    // Idle timeout. A `sid`-scoped session with a valid `expiresAt` (the
    // remember-me / absolute lifetime bound) can still sit unused for far
    // longer than that if nothing else checks activity — this is the check
    // that actually enforces "signed out after N minutes of inactivity"
    // rather than just "signed out eventually".
    if (now.getTime() - session.lastActivityAt.getTime() > IDLE_TIMEOUT_MS) {
      await idpPrisma.userSession
        .update({ where: { id: session.id }, data: { isActive: false } })
        .catch(() => {});
      throw new UnauthorizedException("Session timed out due to inactivity");
    }

    // Touch is fire-and-forget: it must never slow down or fail the request
    // it is riding along on.
    idpPrisma.userSession
      .update({ where: { id: session.id }, data: { lastActivityAt: now } })
      .catch(() => {});

    request.user = decoded;
    return true;
  }
}
