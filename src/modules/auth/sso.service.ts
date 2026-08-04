import {
  Injectable,
  BadRequestException,
  NotFoundException,
} from "@nestjs/common";
import { idpPrisma, prisma, runWithTenantSession } from "@unerp/database";
import { signSessionToken } from "@unerp/auth";

interface SsoProfile {
  email: string;
  firstName?: string;
  lastName?: string;
  nameId?: string;
  groups?: string[];
  provider: "SAML" | "OIDC";
}

@Injectable()
export class SsoService {
  async processSsoLogin(tenantSlug: string, profile: SsoProfile) {
    const tenant = await prisma.tenant.findUnique({
      where: { slug: tenantSlug },
    });
    if (!tenant) throw new NotFoundException("Tenant not found");

    // JIT user provisioning — find or create user from SSO attributes.
    // The SSO callback is unauthenticated, so no tenant session exists yet;
    // run the provisioning queries inside an explicit tenant session so the
    // RLS policies on users/roles accept them (#21 Track C).
    const user = await runWithTenantSession(
      { tenantId: tenant.id, userId: "sso-jit" },
      async () => {
        let existing = await idpPrisma.user.findFirst({
          where: { tenantId: tenant.id, email: profile.email.toLowerCase() },
        });

        if (!existing) {
          existing = await idpPrisma.user.create({
            data: {
              tenantId: tenant.id,
              email: profile.email.toLowerCase(),
              firstName:
                profile.firstName || profile.email.split("@")[0] || "SSO",
              lastName: profile.lastName || "User",
              status: "ACTIVE",
              passwordHash: null,
            },
          });

          // Assign default role
          const viewerRole = await idpPrisma.role.findFirst({
            where: { tenantId: tenant.id, name: "Viewer" },
          });
          if (viewerRole) {
            await idpPrisma.userRole.create({
              data: { userId: existing.id, roleId: viewerRole.id },
            });
          }
        }
        return existing;
      },
    );

    if (user.status !== "ACTIVE") {
      throw new BadRequestException(`Account is ${user.status?.toLowerCase()}`);
    }

    // Get roles (same explicit tenant session — RLS on the included Role rows)
    const userRoles = await runWithTenantSession(
      { tenantId: tenant.id, userId: user.id },
      () =>
        idpPrisma.userRole.findMany({
          where: { userId: user.id },
          include: { role: true },
        }),
    );
    const roles = userRoles.map((ur) => ur.role.name);

    // Generate token
    const token = signSessionToken({
      userId: user.id,
      tenantId: tenant.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      roles,
      ssoProvider: profile.provider,
    });

    // Update last login
    await runWithTenantSession({ tenantId: tenant.id, userId: user.id }, () =>
      idpPrisma.user.update({
        where: { id: user.id },
        data: { lastLoginAt: new Date() },
      }),
    );

    return {
      token,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        roles,
      },
      tenant: { id: tenant.id, name: tenant.name, slug: tenant.slug },
    };
  }

  async getSsoConfig(tenantId: string) {
    const setting = await prisma.setting.findFirst({
      where: { tenantId, key: "sso_config" },
    });
    return setting ? JSON.parse(String(setting.value)) : null;
  }

  async saveSsoConfig(tenantId: string, config: Record<string, unknown>) {
    await prisma.setting.upsert({
      where: { tenantId_key: { tenantId, key: "sso_config" } },
      create: { tenantId, key: "sso_config", value: JSON.stringify(config) },
      update: { value: JSON.stringify(config) },
    });
    return { saved: true };
  }

  async getSsoConfigByTenantSlug(tenantSlug: string) {
    const tenant = await prisma.tenant.findUnique({
      where: { slug: tenantSlug },
    });
    if (!tenant) return null;
    return this.getSsoConfig(tenant.id);
  }
}
