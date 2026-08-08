import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from "@nestjs/common";
import type { Request } from "express";
import { idpPrisma, prisma } from "@kannan19302/database";
import { hashApiKey } from "../auth/api-key.util";

const API_KEY_HEADER = "x-api-key";

/**
 * Service-to-service authentication. Verifies the `x-api-key` header against an
 * ACTIVE, unexpired `ApiKey` row and attaches a minimal tenant-scoped principal
 * to the request so downstream tenant scoping works without a user JWT.
 *
 * Apply with `@UseGuards(ApiKeyGuard)` on integration/public-API controllers.
 */
@Injectable()
export class ApiKeyGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();
    const raw = req.headers[API_KEY_HEADER];

    if (!raw || typeof raw !== "string") {
      throw new UnauthorizedException("Missing API key");
    }

    const key = await idpPrisma.apiKey.findUnique({
      where: { hashedKey: hashApiKey(raw) },
    });

    if (!key || key.status !== "ACTIVE") {
      throw new UnauthorizedException("Invalid or revoked API key");
    }
    if (key.expiresAt && key.expiresAt.getTime() < Date.now()) {
      throw new UnauthorizedException("API key expired");
    }

    // Optional IP allow-list.
    if (key.ipWhitelist) {
      const allowed = key.ipWhitelist.split(",").map((s) => s.trim());
      const ip = req.ip ?? "";
      if (allowed.length > 0 && !allowed.includes(ip)) {
        throw new UnauthorizedException("Source IP not allowed for this key");
      }
    }

    // Attach a principal compatible with tenant-scoped handlers/interceptors.
    (req as Request & { user?: unknown }).user = {
      tenantId: key.tenantId,
      userId: `apikey:${key.id}`,
      apiKeyId: key.id,
      scopes: key.apiScopes?.split(",") ?? [],
    };

    return true;
  }
}
