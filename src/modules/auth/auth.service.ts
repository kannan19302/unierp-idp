import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
  NotFoundException,
  Logger,
  Optional,
} from "@nestjs/common";
import { InjectQueue } from "@nestjs/bullmq";
import { Queue } from "bullmq";
import { EventEmitter2 } from "@nestjs/event-emitter";
import { randomBytes, createHash, randomUUID, randomInt } from "node:crypto";
import * as webPush from "web-push";
import { idpPrisma, prisma, runWithTenantSession } from "@kannan19302/database";
import { IdpModels } from "@kannan19302/database";
import {
  hashPassword,
  comparePassword,
  signSessionToken,
  signTypedToken,
  verifyTypedToken,
  TOKEN_TYPE,
} from "@kannan19302/auth";
import {
  RegisterInput,
  LoginInput,
  ForgotPasswordInput,
  ResetPasswordInput,
  VerifyEmailInput,
  ResendVerificationInput,
} from "@kannan19302/shared";
import {
  generateTotpSecret,
  buildTotpEnrollment,
  verifyTotp,
  generateRecoveryCodes,
  matchRecoveryCode,
  createResetToken,
  hashResetToken,
  encryptSecret,
  decryptSecret,
} from "./auth-crypto";
import { ProvisioningService } from "./provisioning.service";
import { PlatformCredentialsService } from "../../common/platform-credentials/platform-credentials.service";

/** Failed logins allowed before the account is temporarily locked. */
const MAX_FAILED_ATTEMPTS = 5;
/** How long an account stays locked after too many failed logins. */
const LOCK_DURATION_MS = 15 * 60 * 1000;
/** How long the between-steps MFA challenge token is valid. */
const MFA_CHALLENGE_TTL = "5m";
/** How long a push-approval request stays pending before the login page falls back to a manual code. */
const MFA_PUSH_TTL_MS = 2 * 60 * 1000;

// VAPID details are applied lazily per-send (see AuthService.configureWebPush)
// rather than once at module load, so a key saved from the SaaS Portal
// Settings -> Integrations UI takes effect without an API restart.
/** Ties a stored challenge row to its JWT without persisting the bearer token itself. */
const hashChallengeToken = (token: string) =>
  createHash("sha256").update(token).digest("hex");
/** How long a password-reset token is valid. */
const RESET_TOKEN_TTL_MS = 60 * 60 * 1000;
/** How long an email-verification token is valid. */
const VERIFY_TOKEN_TTL_MS = 24 * 60 * 60 * 1000;
/** Stable catalog key for the shared "Free Trial" SaaSPlan every new tenant's TenantSubscription links to. */
const FREE_TRIAL_PLAN_KEY = "free-trial";
/** Full-feature evaluation window (AUTH_BILLING_PROGRAM Phase 2.3). */
const TRIAL_DURATION_MS = 30 * 24 * 60 * 60 * 1000;
/**
 * Access-token lifetime. Short-lived by design (Phase 1.2): the rotating
 * refresh token silently renews it, and revoking the session kills both.
 */
const ACCESS_TOKEN_TTL = (process.env.ACCESS_TOKEN_TTL || "15m") as Parameters<
  typeof signSessionToken
>[1];
/** Refresh-token lifetime for a normal login. */
const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000;
/** Refresh-token lifetime when the user checked "Remember me". */
const REFRESH_TTL_REMEMBER_MS = 30 * 24 * 60 * 60 * 1000;

/** Request-derived context recorded on a session for the "active sessions" UI. */
export interface SessionContext {
  ipAddress?: string | null;
  userAgent?: string | null;
  device?: string | null;
  /** Multi-client device identity (Flutter mobile/desktop) — null for browser sessions. */
  deviceId?: string | null;
  platform?: string | null;
  appVersion?: string | null;
}

/** Reduces a raw User-Agent string to a short "OS • Browser" label for the sessions UI. */
function parseUserAgent(ua?: string | null): {
  device: string | null;
  browser: string | null;
} {
  if (!ua) return { device: null, browser: null };
  const device = /windows/i.test(ua)
    ? "Windows"
    : /mac os/i.test(ua)
      ? "macOS"
      : /android/i.test(ua)
        ? "Android"
        : /iphone|ipad/i.test(ua)
          ? "iOS"
          : /linux/i.test(ua)
            ? "Linux"
            : null;
  const browser = /edg\//i.test(ua)
    ? "Edge"
    : /chrome\//i.test(ua)
      ? "Chrome"
      : /firefox\//i.test(ua)
        ? "Firefox"
        : /safari\//i.test(ua)
          ? "Safari"
          : /curl\//i.test(ua)
            ? "curl"
            : null;
  return { device, browser };
}

/** Simple geo-hint resolver based on IP address. */
function getGeoHint(ip?: string | null): string | null {
  if (!ip) return null;
  if (
    ip === "127.0.0.1" ||
    ip === "::1" ||
    ip.startsWith("192.168.") ||
    ip.startsWith("10.") ||
    ip.startsWith("::ffff:127.0.0.1")
  ) {
    return "Local Network";
  }
  return "United States (GeoIP Stub)";
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    @Optional()
    @InjectQueue("email")
    private readonly emailQueue?: Queue,
    @Optional()
    private readonly provisioningService?: ProvisioningService,
    @Optional()
    private readonly eventEmitter?: EventEmitter2,
    @Optional()
    private readonly platformCredentialsService?: PlatformCredentialsService,
  ) {}

  /**
   * Applies VAPID details to the shared web-push instance from DB-first
   * credentials (falling back to env), then reports whether push is usable.
   * Called before every send rather than once at boot, mirroring the lazy
   * Stripe-client/SMTP-transporter pattern elsewhere in this codebase.
   */
  private async configureWebPush(): Promise<boolean> {
    const creds = this.platformCredentialsService
      ? await this.platformCredentialsService.get("web-push")
      : {};
    const publicKey = creds.publicKey || process.env.VAPID_PUBLIC_KEY;
    const privateKey = creds.privateKey || process.env.VAPID_PRIVATE_KEY;
    if (!publicKey || !privateKey) return false;
    webPush.setVapidDetails(
      creds.subject || process.env.VAPID_SUBJECT || "mailto:admin@kannan19302.dev",
      publicKey,
      privateKey,
    );
    return true;
  }

  private get isProduction() {
    return process.env.NODE_ENV === "production";
  }

  private get appUrl() {
    return process.env.APP_URL || "http://localhost:3000";
  }

  /**
   * Enqueues a transactional auth email. Delivery is best-effort: auth flows
   * must never fail because the email queue is unavailable (the developer
   * link / resend path covers recovery).
   */
  private async dispatchAuthEmail(payload: {
    to: string;
    tenantId: string;
    subject: string;
    body: string;
  }) {
    try {
      await this.emailQueue?.add("send", payload);
      this.logger.log(`[email] "${payload.subject}" queued for ${payload.to}`);
    } catch (err) {
      this.logger.warn(
        `[email] queue unavailable, "${payload.subject}" for ${payload.to} not sent: ${err instanceof Error ? err.message : err}`,
      );
    }
  }

  /**
   * Used by the registration wizard's real-time email check. A brand-new
   * signup always gets its own tenant (User is unique per [tenantId, email],
   * not globally) so this isn't a hard registration constraint — it's a
   * friendly nudge: if the email already has an account in ANY tenant, tell
   * the user so they can log in instead of accidentally spinning up a
   * duplicate organization.
   */
  async checkEmailAvailability(email: string): Promise<{ available: boolean }> {
    // Runs before any tenant context exists — a plain cross-tenant query
    // would be blocked by RLS under the unerp_api runtime role, so reuse the
    // same narrow SECURITY DEFINER lookup function login() uses (Track C / #21).
    const users = await prisma.$queryRaw<Array<{ id: string }>>`
      SELECT id FROM auth_lookup_user_tenants(${email.toLowerCase().trim()})
    `;
    return { available: users.length === 0 };
  }

  /**
   * Registers a new tenant along with its organization, default roles, and super admin user.
   */
  async register(dto: RegisterInput) {
    const baseSlug =
      dto.organizationName
        .toLowerCase()
        .trim()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "") || "workspace";

    // A taken slug gets a suffix; it does not reject the signup.
    //
    // Registration used to fail with "An organization with a similar name
    // already exists" whenever the derived slug was taken. Two problems with
    // that. Company names are not globally unique — there are many businesses
    // called Acme, and one tenant claiming the name locked out every other
    // customer who shares it. And the message answered a question the caller
    // has no right to ask: it confirmed whether a given company is on the
    // platform, turning the public signup form into a tenant-enumeration oracle
    // for anyone with a list of company names.
    //
    // The slug is a URL and must be unique. The display name need not be, and
    // is stored exactly as the customer typed it.
    let slug = baseSlug;
    for (let attempt = 2; attempt <= 100; attempt += 1) {
      const taken = await prisma.tenant.findUnique({ where: { slug } });
      if (!taken) break;
      slug = `${baseSlug}-${attempt}`;
    }

    const tenantId = dto.tenantId || randomUUID();
    const updateProgress = async (
      pct: number,
      step: string,
      status: "pending" | "success" | "failed" = "pending",
      err?: string,
    ) => {
      if (this.provisioningService) {
        await this.provisioningService.setProgress(
          tenantId,
          pct,
          step,
          status,
          err,
        );
      }
    };

    try {
      await updateProgress(10, "Initializing setup...");

      // Hash the administrator's password
      const hashedPassword = await hashPassword(dto.password);

      // Run creation in a transaction
      const result = await idpPrisma.$transaction(async (tx) => {
        await updateProgress(15, "Creating secure organization partition...");
        // 1. Create Tenant
        const tenant = await prisma.tenant.create({
          data: {
            id: tenantId,
            name: dto.organizationName,
            slug,
            plan: "free",
            status: "ACTIVE",
            settings: {
              businessType: dto.businessType || null,
              country: dto.country || null,
              language: dto.language || null,
              estimatedUsers: dto.estimatedUsers || null,
              logoUrl: dto.logoUrl || null,
              industry: dto.industry || null,
              // Compliance record of consent — dto.termsAccepted is already
              // required true by registerSchema; this is when, not whether.
              termsAcceptedAt: new Date().toISOString(),
              onboardingChecklist: {
                profile: false,
                logo: dto.logoUrl ? true : false,
                invite: false,
                app: false,
                plan: false,
                dashboard: false,
              },
            },
          },
        });

        // Registration is unauthenticated, so no tenant session exists yet and
        // the RLS session GUC is never set by the client extension. Set it
        // transaction-locally so the inserts below pass the RLS policies on
        // roles/users/organizations/departments (#21 Track C).
        await tx.$executeRaw`SELECT set_config('app.current_tenant_id', ${tenant.id}, true)`;

        await updateProgress(30, "Bootstrapping default roles...");
        // 2. Create default roles for the tenant
        const defaultRolesConfig = {
          SUPER_ADMIN: {
            name: "Super Admin",
            description: "Full access to all features",
            permissions: ["*"],
          },
          ADMIN: {
            name: "Admin",
            description: "Administrative access with user management",
            permissions: [
              "admin.*",
              "finance.*",
              "hr.*",
              "crm.*",
              "inventory.*",
            ],
          },
          VIEWER: {
            name: "Viewer",
            description: "Read-only access to all modules",
            permissions: [
              "finance.invoice.read",
              "finance.report.read",
              "hr.employee.read",
              "crm.contact.read",
              "inventory.product.read",
            ],
          },
        };

        const rolesMap: Record<string, string> = {};
        for (const [key, role] of Object.entries(defaultRolesConfig)) {
          const dbRole = await tx.role.create({
            data: {
              tenantId: tenant.id,
              name: role.name,
              description: role.description,
              isSystem: true,
              permissions: JSON.stringify(role.permissions),
            },
          });
          rolesMap[key] = dbRole.id;
        }

        await updateProgress(50, "Creating administrator profile...");
        // 3. Create User
        const user = await tx.user.create({
          data: {
            tenantId: tenant.id,
            email: dto.email.toLowerCase(),
            passwordHash: hashedPassword,
            passwordChangedAt: new Date(),
            firstName: dto.firstName,
            lastName: dto.lastName,
            status: "ACTIVE",
          },
        });

        await updateProgress(65, "Assigning administrative privileges...");
        // 4. Assign SUPER_ADMIN role to user
        const superAdminRoleId = rolesMap["SUPER_ADMIN"];
        if (superAdminRoleId) {
          await tx.userRole.create({
            data: {
              userId: user.id,
              roleId: superAdminRoleId,
            },
          });
        }

        await updateProgress(
          80,
          "Setting up primary organization structure...",
        );

        // 5 & 6. Organization and departments, on the MAIN client — so they
        // need their own tenant session.
        //
        // These models live in the business schema, not the IdP realm (§ 5.2),
        // so they are written through `prisma` rather than `tx`. That means a
        // different client on a different connection, and the
        // `set_config('app.current_tenant_id', …, true)` above is
        // transaction-local to `tx`'s connection only. Without this wrapper the
        // inserts arrive with no tenant GUC set and Postgres rejects them:
        //
        //   42501: new row violates row-level security policy for table
        //          "organizations"
        //
        // This never surfaced before because the application had only ever been
        // run as the database owner, which is a superuser, and a superuser
        // bypasses RLS outright. Running as `unerp_api` (NOBYPASSRLS) — which
        // § 5.1 requires and the container stack finally does — is what exposed
        // it. The same § 5.1 lesson as the isolation test: a check performed
        // over the owner connection proves nothing about the guarantee.
        const { org } = await runWithTenantSession(
          { tenantId: tenant.id, userId: user.id },
          async () => {
            const created = await prisma.organization.create({
              data: {
                tenantId: tenant.id,
                name: dto.organizationName,
                currency: dto.currency || "USD",
                timezone: dto.timezone || "UTC",
              },
            });

            await updateProgress(90, "Seeding default departments...");
            const depts = [
              "Finance",
              "Human Resources",
              "Sales",
              "Operations",
            ];
            for (const deptName of depts) {
              await prisma.department.create({
                data: {
                  tenantId: tenant.id,
                  orgId: created.id,
                  name: deptName,
                  code: deptName.toUpperCase(),
                },
              });
            }

            return { org: created };
          },
        );

        await updateProgress(
          95,
          "Generating secure email verification token...",
        );
        // 7. Mint the email verification token inside the same transaction (the
        // RLS GUC set above covers this insert too).
        const { plain: verificationToken, hash: verificationHash } =
          createResetToken();
        await tx.emailVerificationToken.create({
          data: {
            userId: user.id,
            tenantId: tenant.id,
            tokenHash: verificationHash,
            expiresAt: new Date(Date.now() + VERIFY_TOKEN_TTL_MS),
          },
        });

        // 8. Start the 30-day full-feature evaluation as an explicit,
        // queryable subscription row (AUTH_BILLING_PROGRAM Phase 2.3) —
        // rather than only inferring "still trialing" from tenant.createdAt,
        // which is what TenantWriteGuard falls back to for tenants that
        // predate this. FREE_TRIAL_PLAN_KEY is a stable catalog row shared
        // by every tenant's trial, not tenant-scoped.
        const freePlan = await prisma.saaSPlan.upsert({
          where: { stripePriceId: FREE_TRIAL_PLAN_KEY },
          update: {},
          create: {
            name: "Free Trial",
            stripePriceId: FREE_TRIAL_PLAN_KEY,
            maxUsers: 5,
            maxStorage: 1024,
            features: [],
          },
        });
        const trialStart = new Date();
        const trialEnd = new Date(trialStart.getTime() + TRIAL_DURATION_MS);
        // Tenant-scoped, on the main client — so it needs a tenant session for
        // the same reason the organization above does. `saaSPlan` immediately
        // before it does not: the trial plan is a shared catalogue row and
        // carries no `tenantId`, which is why it succeeds without one.
        await runWithTenantSession(
          { tenantId: tenant.id, userId: user.id },
          () =>
            prisma.tenantSubscription.create({
              data: {
                tenantId: tenant.id,
                planId: freePlan.id,
                status: "TRIAL",
                startDate: trialStart,
                endDate: trialEnd,
              },
            }),
        );

        return {
          user: {
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
          },
          tenant: {
            id: tenant.id,
            name: tenant.name,
            slug: tenant.slug,
          },
          verificationToken,
        };
      });

      const verificationLink = `${this.appUrl}/verify-email?token=${result.verificationToken}`;
      await this.dispatchAuthEmail({
        to: result.user.email,
        tenantId: result.tenant.id,
        subject: "Verify your UniERP email address",
        body: `Welcome to UniERP! Verify your email address to secure your new workspace: ${verificationLink}`,
      });

      // Phase 5: new tenants start with zero auto-installed apps (only kernel
      // apps App Store + SaaS Portal are visible by default). The event fires
      // asynchronously so a catalog hiccup never blocks registration itself.
      this.eventEmitter?.emit("tenant.registered", {
        tenantId: result.tenant.id,
        userId: result.user.id,
      });

      await updateProgress(
        100,
        "Setup complete! Redirecting to workspace...",
        "success",
      );

      const { verificationToken: _token, ...publicResult } = result;
      if (this.isProduction) {
        return publicResult;
      }
      // Local-dev ergonomics only — mirrors forgotPassword's developer link.
      return { ...publicResult, developerVerificationLink: verificationLink };
    } catch (err: any) {
      await updateProgress(0, "Setup failed", "failed", err.message);
      throw err;
    }
  }

  /**
   * Marks the user's email verified using a single-use token, then burns it.
   * Unauthenticated: resolves tenant context through the narrow
   * SECURITY DEFINER token lookup (Track C / #21).
   */
  async verifyEmail(dto: VerifyEmailInput) {
    const tokenHash = hashResetToken(dto.token);
    const rows = await prisma.$queryRaw<
      Array<{
        id: string;
        user_id: string;
        tenant_id: string;
        expires_at: Date;
        used_at: Date | null;
      }>
    >`SELECT id, user_id, tenant_id, expires_at, used_at FROM auth_lookup_verification_token(${tokenHash})`;

    const record = rows[0];
    if (!record || record.used_at || record.expires_at < new Date()) {
      throw new BadRequestException(
        "Invalid or expired verification link. Request a new one.",
      );
    }

    await runWithTenantSession(
      { tenantId: record.tenant_id, userId: record.user_id },
      () =>
        idpPrisma.$transaction([
          idpPrisma.user.update({
            where: { id: record.user_id },
            data: { emailVerifiedAt: new Date() },
          }),
          idpPrisma.emailVerificationToken.updateMany({
            where: { userId: record.user_id, usedAt: null },
            data: { usedAt: new Date() },
          }),
        ]),
    );

    return { message: "Email verified successfully." };
  }

  /**
   * Re-issues a verification token. Responds identically whether or not the
   * email exists (or is already verified) to avoid account enumeration.
   */
  async resendVerification(dto: ResendVerificationInput) {
    const genericMessage =
      "If an unverified account exists for that email, a new verification link has been sent.";

    const users = await prisma.$queryRaw<
      Array<{ id: string; tenant_id: string }>
    >`SELECT id, tenant_id FROM auth_lookup_user_tenants(${dto.email.toLowerCase()})`;
    const match = users[0];
    if (!match) return { message: genericMessage };

    const link = await runWithTenantSession(
      { tenantId: match.tenant_id, userId: match.id },
      async () => {
        const user = await idpPrisma.user.findFirst({
          where: { id: match.id },
        });
        if (!user || user.emailVerifiedAt) return null;

        const { plain, hash } = createResetToken();
        await idpPrisma.$transaction([
          idpPrisma.emailVerificationToken.updateMany({
            where: { userId: user.id, usedAt: null },
            data: { usedAt: new Date() },
          }),
          idpPrisma.emailVerificationToken.create({
            data: {
              userId: user.id,
              tenantId: user.tenantId,
              tokenHash: hash,
              expiresAt: new Date(Date.now() + VERIFY_TOKEN_TTL_MS),
            },
          }),
        ]);
        return `${this.appUrl}/verify-email?token=${plain}`;
      },
    );

    if (link) {
      await this.dispatchAuthEmail({
        to: dto.email.toLowerCase(),
        tenantId: match.tenant_id,
        subject: "Verify your UniERP email address",
        body: `Verify your email address: ${link}`,
      });
      if (!this.isProduction) {
        return { message: genericMessage, developerVerificationLink: link };
      }
    }
    return { message: genericMessage };
  }

  /**
   * Resolves a user's role names and flattened permission list.
   */
  private async resolveRolesAndPermissions(userId: string, tenantId?: string) {
    // UserRole has no tenantId of its own, but it `include`s Role, which is
    // RLS-protected. § 5.1: a join table is exempt from where-clause injection
    // and NOT from the session GUC, because the relation it pulls in is
    // tenant-scoped. Without a session this returns roles with empty relations
    // under the NOBYPASSRLS role — or throws, which is what it did.
    const fetchRoles = () =>
      idpPrisma.userRole.findMany({ where: { userId }, include: { role: true } });
    const userRoles = (await (tenantId
      ? runWithTenantSession({ tenantId, userId }, fetchRoles)
      : fetchRoles())) as unknown as Array<IdpModels.UserRole & { role: IdpModels.Role }>;

    const roles = userRoles.map((ur) => ur.role.name);
    const permissions: string[] = [];
    for (const ur of userRoles) {
      try {
        const perms = JSON.parse(ur.role.permissions as string);
        if (Array.isArray(perms)) permissions.push(...perms);
      } catch {
        // Skip malformed permissions
      }
    }
    return { roles, permissions };
  }

  /**
   * Builds the standard authenticated login response with a fresh session token.
   * A revocable `UserSession` row is created and its id embedded as the token's
   * `sid`, so JwtAuthGuard can reject the token the moment the session is revoked.
   */
  async issueSession(
    user: any,
    context?: SessionContext,
    opts?: { rememberMe?: boolean },
  ) {
    if (!user.tenant) {
      user.tenant = await prisma.tenant.findUnique({
        where: { id: user.tenantId },
      });
    }
    return runWithTenantSession(
      { tenantId: user.tenantId, userId: user.id },
      async () => {
        const { roles, permissions } = await this.resolveRolesAndPermissions(
          user.id,
        );

        // Create the session first so its id can be sealed into the token.
        // The session (and its rotating refresh token) governs lifetime; the
        // access token itself is short-lived (ACCESS_TOKEN_TTL).
        const sid = randomBytes(18).toString("hex");
        const rememberMe = opts?.rememberMe ?? false;
        const refreshTtlMs = rememberMe
          ? REFRESH_TTL_REMEMBER_MS
          : REFRESH_TTL_MS;
        const refreshToken = randomBytes(32).toString("hex");
        const refreshExpiresAt = new Date(Date.now() + refreshTtlMs);
        const parsedUa = parseUserAgent(context?.userAgent);
        await idpPrisma.userSession.create({
          data: {
            id: sid,
            tenantId: user.tenantId,
            userId: user.id,
            token: sid,
            ipAddress: context?.ipAddress ?? null,
            browser: parsedUa.browser,
            device: context?.device ?? parsedUa.device,
            expiresAt: refreshExpiresAt,
            refreshTokenHash: hashResetToken(refreshToken),
            refreshExpiresAt,
            rememberMe,
            deviceId: context?.deviceId ?? null,
            platform: context?.platform ?? null,
            appVersion: context?.appVersion ?? null,
          },
        });

        // Record successful login history
        await prisma.loginHistory.create({
          data: {
            tenantId: user.tenantId,
            userId: user.id,
            status: "SUCCESS",
            ipAddress: context?.ipAddress ?? null,
            browser: parsedUa.browser,
            device: context?.device ?? parsedUa.device,
            location: context?.ipAddress ? getGeoHint(context.ipAddress) : null,
          },
        });

        const token = signSessionToken(
          {
            sid,
            userId: user.id,
            tenantId: user.tenantId,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            roles,
            // The API's RbacGuard reads `permissions` from the token claims —
            // it does not resolve roles to permissions itself, by design, so a
            // request costs no database round trip to authorise.
            //
            // Without this claim the guard saw an empty permission set and
            // denied EVERY authorised endpoint with 403, including for a Super
            // Admin holding "*". Authentication succeeded and authorisation
            // could not: the two services agreed on the signature and disagreed
            // on the payload.
            permissions,
          },
          ACCESS_TOKEN_TTL,
        );

        await idpPrisma.user.update({
          where: { id: user.id },
          data: {
            lastLoginAt: new Date(),
            failedLoginAttempts: 0,
            lockedUntil: null,
          },
        });

        return {
          token,
          // Consumed by the controller to set the httpOnly refresh cookie;
          // stripped from the JSON body before it reaches the client.
          refreshToken,
          refreshExpiresAt,
          user: {
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            avatar: user.avatar,
            roles,
            permissions,
          },
          tenant: {
            id: user.tenant.id,
            name: user.tenant.name,
            slug: user.tenant.slug,
          },
        };
      },
    );
  }

  /**
   * Rotates a refresh token: validates the presented (hashed) token, issues a
   * fresh access token and a fresh refresh token, and invalidates the old
   * refresh token in the same update. A replayed old token no longer matches
   * any hash and is rejected. Unauthenticated: resolves tenant context via the
   * SECURITY DEFINER lookup (Track C / #21).
   */
  async refreshSession(refreshToken: string, context?: SessionContext) {
    const invalid = () =>
      new UnauthorizedException("Invalid or expired refresh token");
    if (!refreshToken) throw invalid();

    const hash = hashResetToken(refreshToken);
    const rows = await prisma.$queryRaw<
      Array<{
        id: string;
        user_id: string;
        tenant_id: string;
        refresh_expires_at: Date | null;
        is_active: boolean;
        remember_me: boolean;
      }>
    >`SELECT id, user_id, tenant_id, refresh_expires_at, is_active, remember_me FROM auth_lookup_refresh_token(${hash})`;
    const session = rows[0];

    if (
      !session ||
      !session.is_active ||
      !session.refresh_expires_at ||
      session.refresh_expires_at < new Date()
    ) {
      throw invalid();
    }

    return runWithTenantSession(
      { tenantId: session.tenant_id, userId: session.user_id },
      async () => {
        const user = await idpPrisma.user.findFirst({
          where: { id: session.user_id, status: "ACTIVE" },
        });
        if (!user) throw invalid();

        // Same reason as getProfile: the IdP's User carries a bare tenantId and
        // has no tenant relation, because § 5.2 keeps identity and business data
        // in separate databases. The response below reads tenant.name and
        // tenant.slug, so the record is fetched from the main database here.
        //
        // This did not fail earlier only because the service was running from a
        // stale dist/ — the file did not compile. Deleting dist surfaced it.
        const tenant = await prisma.tenant.findUnique({
          where: { id: user.tenantId },
          select: { id: true, name: true, slug: true },
        });
        if (!tenant) throw invalid();

        // Rotate: sliding expiry, single valid refresh token per session.
        const nextRefreshToken = randomBytes(32).toString("hex");
        const refreshTtlMs = session.remember_me
          ? REFRESH_TTL_REMEMBER_MS
          : REFRESH_TTL_MS;
        const refreshExpiresAt = new Date(Date.now() + refreshTtlMs);
        await idpPrisma.userSession.update({
          where: { id: session.id },
          data: {
            refreshTokenHash: hashResetToken(nextRefreshToken),
            refreshExpiresAt,
            expiresAt: refreshExpiresAt,
            lastActivityAt: new Date(),
            ipAddress: context?.ipAddress ?? undefined,
            appVersion: context?.appVersion ?? undefined,
          },
        });

        const { roles, permissions } = await this.resolveRolesAndPermissions(
          user.id,
        );
        const token = signSessionToken(
          {
            sid: session.id,
            userId: user.id,
            tenantId: user.tenantId,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            roles,
            // The API's RbacGuard reads `permissions` from the token claims —
            // it does not resolve roles to permissions itself, by design, so a
            // request costs no database round trip to authorise.
            //
            // Without this claim the guard saw an empty permission set and
            // denied EVERY authorised endpoint with 403, including for a Super
            // Admin holding "*". Authentication succeeded and authorisation
            // could not: the two services agreed on the signature and disagreed
            // on the payload.
            permissions,
          },
          ACCESS_TOKEN_TTL,
        );

        return {
          token,
          refreshToken: nextRefreshToken,
          refreshExpiresAt,
          user: {
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            avatar: user.avatar,
            roles,
            permissions,
          },
          tenant: {
            id: tenant.id,
            name: tenant.name,
            slug: tenant.slug,
          },
        };
      },
    );
  }

  /**
   * Authenticates a user and issues a JWT token (or an MFA challenge).
   */
  async login(
    dto: LoginInput & { tenantSlug?: string },
    context?: SessionContext,
  ) {
    let tenantId = "";

    if (dto.tenantSlug) {
      const tenant = await prisma.tenant.findUnique({
        where: { slug: dto.tenantSlug },
      });
      if (!tenant) {
        // Do not distinguish "tenant missing" from "bad credentials".
        throw new UnauthorizedException("Invalid credentials");
      }
      tenantId = tenant.id;
    } else {
      // Look up which tenant(s) this email belongs to. This runs before any
      // tenant context exists, so a plain cross-tenant query would be blocked
      // by RLS under the unerp_api runtime role — use the narrow
      // SECURITY DEFINER lookup function instead (Track C / #21).
      const users = await prisma.$queryRaw<
        Array<{ id: string; tenant_id: string }>
      >`
        SELECT id, tenant_id FROM auth_lookup_user_tenants(${dto.email.toLowerCase()})
      `;

      if (users.length === 0) {
        throw new UnauthorizedException("Invalid credentials");
      }
      if (users.length > 1) {
        throw new BadRequestException(
          "Multiple organizations use this email. Please provide your Organization Slug.",
        );
      }

      const targetUser = users[0];
      if (targetUser) {
        tenantId = targetUser.tenant_id;
      }
    }

    // Find user within the specified tenant scope. Run inside a tenant
    // session so the RLS-enforcing unerp_api role can see the row.
    const user = await runWithTenantSession({ tenantId, userId: "" }, () =>
      idpPrisma.user.findFirst({
        where: {
          tenantId,
          email: dto.email.toLowerCase(),
        },
        include: {
          /* tenant: true */
        },
      }),
    );

    if (!user || !user.passwordHash) {
      throw new UnauthorizedException("Invalid credentials");
    }

    // Reject locked accounts before touching the password.
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      const mins = Math.ceil((user.lockedUntil.getTime() - Date.now()) / 60000);
      await this.recordFailedLogin(
        user.id,
        user.tenantId,
        "ACCOUNT_LOCKED",
        context,
      );
      throw new UnauthorizedException(
        `Account locked due to failed login attempts. Try again in ${mins} minute(s).`,
      );
    }

    // Check CAPTCHA if configured and failed threshold met
    const captchaCreds = this.platformCredentialsService
      ? await this.platformCredentialsService.get("captcha")
      : {};
    const captchaSecret =
      captchaCreds.secretKey || process.env.CAPTCHA_SECRET_KEY;
    const captchaThreshold = parseInt(
      captchaCreds.threshold || process.env.CAPTCHA_THRESHOLD || "3",
      10,
    );
    if (captchaSecret && user.failedLoginAttempts >= captchaThreshold) {
      if (!dto.captchaToken) {
        throw new BadRequestException({
          captchaRequired: true,
          provider:
            captchaCreds.provider || process.env.CAPTCHA_PROVIDER || "hcaptcha",
          siteKey:
            captchaCreds.siteKey ||
            process.env.CAPTCHA_SITE_KEY ||
            "10000000-ffff-ffff-ffff-000000000001",
          message: "CAPTCHA verification is required.",
        });
      }
      const isCaptchaValid = await this.verifyCaptcha(dto.captchaToken);
      if (!isCaptchaValid) {
        throw new BadRequestException(
          "Invalid CAPTCHA token. Please try again.",
        );
      }
    }

    // Validate password
    const isPasswordValid = await comparePassword(
      dto.password,
      user.passwordHash,
    );
    if (!isPasswordValid) {
      await this.registerFailedAttempt(
        user.id,
        user.tenantId,
        user.failedLoginAttempts,
        context,
      );
      throw new UnauthorizedException("Invalid credentials");
    }

    if (user.status !== "ACTIVE") {
      await this.recordFailedLogin(
        user.id,
        user.tenantId,
        `ACCOUNT_STATUS_${user.status}`,
        context,
      );
      throw new UnauthorizedException(
        `Account is ${user.status.toLowerCase()}`,
      );
    }

    // Password is correct — clear any accumulated failure count.
    if (user.failedLoginAttempts > 0 || user.lockedUntil) {
      await runWithTenantSession({ tenantId, userId: user.id }, () =>
        idpPrisma.user.update({
          where: { id: user.id },
          data: { failedLoginAttempts: 0, lockedUntil: null },
        }),
      );
    }

    // Second factor: issue a short-lived challenge token instead of the user id,
    // so /mfa/verify-login cannot be called for an arbitrary account.
    if (user.mfaEnabled) {
      const challengeToken = signTypedToken(
        TOKEN_TYPE.MFA_CHALLENGE,
        { userId: user.id, tenantId: user.tenantId },
        MFA_CHALLENGE_TTL,
      );
      // Best-effort — a user with no registered device (or push not configured)
      // just falls back to typing the 6-digit code, which always still works.
      const pushSent = await this.sendMfaPushChallenge(
        challengeToken,
        user.id,
        user.tenantId,
      ).catch(() => false);
      return {
        mfaRequired: true,
        challengeToken,
        pushSent,
        message: "MFA authentication required.",
      } as const;
    }

    return this.issueSession(user, context, { rememberMe: dto.rememberMe });
  }

  /**
   * Increments the failed-login counter and locks the account past the threshold.
   */
  private async registerFailedAttempt(
    userId: string,
    tenantId: string,
    current: number,
    context?: SessionContext,
  ) {
    const attempts = current + 1;
    const shouldLock = attempts >= MAX_FAILED_ATTEMPTS;
    await runWithTenantSession({ tenantId, userId }, () =>
      idpPrisma.user.update({
        where: { id: userId },
        data: {
          failedLoginAttempts: shouldLock ? 0 : attempts,
          lockedUntil: shouldLock
            ? new Date(Date.now() + LOCK_DURATION_MS)
            : undefined,
        },
      }),
    );
    await this.recordFailedLogin(
      userId,
      tenantId,
      shouldLock ? "ACCOUNT_LOCKED" : "INVALID_CREDENTIALS",
      context,
    );
  }

  /**
   * Helper to write a failed login history record.
   */
  private async recordFailedLogin(
    userId: string,
    tenantId: string,
    reason: string,
    context?: SessionContext,
  ) {
    const parsedUa = parseUserAgent(context?.userAgent);
    await runWithTenantSession({ tenantId, userId }, () =>
      prisma.loginHistory.create({
        data: {
          tenantId,
          userId,
          status: "FAILED",
          ipAddress: context?.ipAddress ?? null,
          browser: parsedUa.browser,
          device: context?.device ?? parsedUa.device,
          location: context?.ipAddress ? getGeoHint(context.ipAddress) : null,
          failureReason: reason,
        },
      }),
    ).catch((err) => {
      this.logger.warn(
        `Failed to record login failure: ${err instanceof Error ? err.message : err}`,
      );
    });
  }

  /**
   * Verifies hCaptcha or Turnstile CAPTCHA token.
   */
  private async verifyCaptcha(token: string): Promise<boolean> {
    const creds = this.platformCredentialsService
      ? await this.platformCredentialsService.get("captcha")
      : {};
    const secret = creds.secretKey || process.env.CAPTCHA_SECRET_KEY;
    if (!secret) return true;

    const provider =
      creds.provider || process.env.CAPTCHA_PROVIDER || "hcaptcha";
    const url =
      provider === "turnstile"
        ? "https://challenges.cloudflare.com/turnstile/v0/siteverify"
        : "https://hcaptcha.com/siteverify";

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          secret,
          response: token,
        }),
      });
      const data = (await response.json()) as { success: boolean };
      return data.success;
    } catch (err) {
      this.logger.error("CAPTCHA verification failed to connect", err);
      return false;
    }
  }

  /**
   * Returns recent login history records for a user.
   */
  async listLoginHistory(userId: string, tenantId: string) {
    return runWithTenantSession({ tenantId, userId }, () =>
      prisma.loginHistory.findMany({
        where: { userId, tenantId },
        orderBy: { createdAt: "desc" },
        take: 20,
      }),
    );
  }

  /**
   * Returns profile data of the currently authenticated user.
   */
  async getProfile(userId: string, tenantId: string) {
    // Wrapped in a tenant session because `idpPrisma` now enforces RLS.
    //
    // This was an unscoped read on the IdP client. That was invisible while
    // the client had no tenant-context extension and the app connected as the
    // superuser owner; with both fixed, the user row is simply not visible and
    // the endpoint answered 404 for a user who had just logged in successfully.
    const user = await runWithTenantSession({ tenantId, userId }, () =>
      idpPrisma.user.findUnique({ where: { id: userId } }),
    );

    if (!user) {
      throw new NotFoundException("User profile not found");
    }

    // The tenant is fetched separately and deliberately.
    //
    // This method used to read `(user as any).tenant.id` from the IdP user, but
    // the IdP schema has no Tenant model and User has no tenant relation — it
    // carries a bare tenantId. So the expression was always undefined and
    // /auth/me returned 500 for every user, on the endpoint the web app calls
    // immediately after login. The `as any` casts are exactly why the compiler
    // never objected: they asserted a relation that does not exist.
    //
    // § 5.2 splits identity from business data, so the tenant record lives in
    // the main database and is read through the main client.
    const tenant = await prisma.tenant.findUnique({
      where: { id: user.tenantId },
      select: {
        id: true,
        name: true,
        slug: true,
        demoDataLoaded: true,
        settings: true,
      },
    });

    if (!tenant) {
      throw new NotFoundException("Tenant not found for this user");
    }

    const { roles, permissions } = await this.resolveRolesAndPermissions(
      user.id,
      tenantId,
    );

    return {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      avatar: user.avatar,
      roles,
      permissions,
      preferences: user.preferences,
      mfaEnabled: user.mfaEnabled,
      tenant: {
        id: tenant.id,
        name: tenant.name,
        slug: tenant.slug,
        demoDataLoaded: tenant.demoDataLoaded,
        logoUrl:
          (tenant.settings as Record<string, unknown> | null)?.logoUrl ?? null,
      },
    };
  }

  /**
   * Updates profile data of the currently authenticated user.
   */
  async updateProfile(
    userId: string,
    dto: import("@kannan19302/shared").UpdateProfileInput,
  ) {
    const user = await idpPrisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException("User not found");
    }

    const updateData: Record<string, unknown> = {};

    if (dto.newPassword) {
      // Changing a password requires proving knowledge of the current one.
      if (!user.passwordHash)
        throw new BadRequestException("Account does not have a password.");
      if (!dto.currentPassword)
        throw new BadRequestException(
          "Current password is required to set a new one.",
        );
      const isPasswordValid = await comparePassword(
        dto.currentPassword,
        user.passwordHash,
      );
      if (!isPasswordValid)
        throw new UnauthorizedException("Invalid current password");
      updateData.passwordHash = await hashPassword(dto.newPassword);
      updateData.passwordChangedAt = new Date();
    }

    if (dto.firstName) updateData.firstName = dto.firstName;
    if (dto.lastName) updateData.lastName = dto.lastName;

    if (dto.preferences) {
      const currentPrefs = user.preferences as Record<string, unknown>;
      updateData.preferences = { ...currentPrefs, ...dto.preferences };
    }

    const updatedUser = await idpPrisma.user.update({
      where: { id: userId },
      data: updateData,
    });

    // Note: the "profile" onboarding step is now derived live from
    // `User.avatar` (see onboarding.service.ts) rather than manually marked
    // here, so no completeStep call is needed on profile update.

    return {
      id: updatedUser.id,
      firstName: updatedUser.firstName,
      lastName: updatedUser.lastName,
      preferences: updatedUser.preferences,
    };
  }

  /**
   * Lists every tenant this account can sign in to. Identity is email-based:
   * the same verified email in another tenant is the same person, so the list
   * is all ACTIVE user rows sharing the caller's email (Slack-workspace model).
   */
  async listUserTenants(userId: string) {
    const me = await idpPrisma.user.findUnique({
      where: { id: userId },
      select: { email: true, tenantId: true },
    });
    if (!me) throw new NotFoundException("User not found");

    const memberships = await idpPrisma.user.findMany({
      where: { email: me.email, status: "ACTIVE" },
      select: {
        tenantId: true,
      },
      orderBy: { createdAt: "asc" },
    });
    return memberships.map((m) => ({
      /*...m.tenant*/
      current: m.tenantId === me.tenantId,
    }));
  }

  /**
   * Re-issues the session against another tenant the caller's email belongs to.
   * The caller already authenticated (password + MFA where enabled) for this
   * email, so switching does not re-prompt — mirroring how login without a slug
   * resolves the tenant. The old session is revoked before the new one is cut,
   * so exactly one tenant scope is live per switch.
   */
  async switchTenant(
    userId: string,
    currentSid: string | undefined,
    tenantSlug: string,
    context?: SessionContext,
  ) {
    const me = await idpPrisma.user.findUnique({
      where: { id: userId },
      select: { email: true },
    });
    if (!me) throw new UnauthorizedException("Invalid session");

    const target = await idpPrisma.user.findFirst({
      where: {
        email: me.email,
        status: "ACTIVE",
        tenantId: (
          await prisma.tenant.findFirst({ where: { slug: tenantSlug } })
        )?.id,
      },
    });
    if (!target) {
      throw new UnauthorizedException(
        "No active membership in that organization",
      );
    }

    if (currentSid) await this.revokeSessionById(currentSid);
    return this.issueSession(target, context);
  }

  /**
   * Issues a single-use, hashed password reset token. Always responds the same
   * way whether or not the email exists, to avoid account enumeration.
   */
  async forgotPassword(dto: ForgotPasswordInput) {
    const genericMessage =
      "If an account exists for that email, a password reset link has been sent.";

    // Unauthenticated flow: resolve the user through the SECURITY DEFINER
    // lookup — a plain cross-tenant query returns zero rows under RLS
    // (Track C / #21).
    const users = await prisma.$queryRaw<
      Array<{ id: string; tenant_id: string }>
    >`SELECT id, tenant_id FROM auth_lookup_user_tenants(${dto.email.toLowerCase()})`;
    const match = users[0];

    if (!match) {
      return { message: genericMessage };
    }

    // Invalidate any outstanding tokens for this user, then mint a new one.
    const { plain, hash } = createResetToken();
    await runWithTenantSession(
      { tenantId: match.tenant_id, userId: match.id },
      () =>
        idpPrisma.$transaction([
          idpPrisma.passwordResetToken.updateMany({
            where: { userId: match.id, usedAt: null },
            data: { usedAt: new Date() },
          }),
          idpPrisma.passwordResetToken.create({
            data: {
              userId: match.id,
              tenantId: match.tenant_id,
              tokenHash: hash,
              expiresAt: new Date(Date.now() + RESET_TOKEN_TTL_MS),
            },
          }),
        ]),
    );

    const resetLink = `${this.appUrl}/reset-password?token=${plain}`;

    await this.dispatchAuthEmail({
      to: dto.email.toLowerCase(),
      tenantId: match.tenant_id,
      subject: "Reset your UniERP password",
      body: `A password reset was requested for your account. Reset it here: ${resetLink}\nIf you didn't request this, you can ignore this email.`,
    });

    // Never return the token in production; expose it only for local dev ergonomics.
    if (this.isProduction) {
      return { message: genericMessage };
    }
    return { message: genericMessage, developerResetLink: resetLink };
  }

  /**
   * Resets the password using a single-use token, then invalidates the token.
   */
  async resetPassword(dto: ResetPasswordInput) {
    const tokenHash = hashResetToken(dto.token);

    // Unauthenticated flow: resolve tenant context via the SECURITY DEFINER
    // token lookup — RLS blocks a direct cross-tenant read (Track C / #21).
    const rows = await prisma.$queryRaw<
      Array<{
        id: string;
        user_id: string;
        tenant_id: string;
        expires_at: Date;
        used_at: Date | null;
      }>
    >`SELECT id, user_id, tenant_id, expires_at, used_at FROM auth_lookup_reset_token(${tokenHash})`;
    const record = rows[0];

    if (!record || record.used_at || record.expires_at < new Date()) {
      throw new BadRequestException("Invalid or expired password reset token.");
    }

    const hashedPassword = await hashPassword(dto.password);

    await runWithTenantSession(
      { tenantId: record.tenant_id, userId: record.user_id },
      () =>
        idpPrisma.$transaction([
          idpPrisma.user.update({
            where: { id: record.user_id },
            data: {
              passwordHash: hashedPassword,
              passwordChangedAt: new Date(),
              failedLoginAttempts: 0,
              lockedUntil: null,
            },
          }),
          // Burn this and any other outstanding reset tokens for this user.
          idpPrisma.passwordResetToken.updateMany({
            where: { userId: record.user_id, usedAt: null },
            data: { usedAt: new Date() },
          }),
        ]),
    );

    return { message: "Password reset successfully. You can now log in." };
  }

  /**
   * Automatically provisions and logs in a demo user with the specified role.
   * The controller restricts this to non-production environments.
   */
  /**
   * Dev-only shortcut: seeds (or reuses) a single Super Admin account on a
   * shared "system" tenant. HR/Finance/Viewer demo personas were removed —
   * this exists purely to get into a working workspace during local
   * development, not to demonstrate role-based access.
   */
  async loginDemo() {
    const target = {
      email: "admin@kannan19302.dev",
      firstName: "System",
      lastName: "Administrator",
      roleName: "Super Admin",
    };

    // 1. Get-or-create the shared dev tenant + everything inside it inside a
    // single transaction with the RLS GUC set, matching register()'s
    // pattern — this whole path runs unauthenticated, so no tenant session
    // exists yet and the inserts would otherwise fail Track C RLS (#21).
    const user = await idpPrisma.$transaction(async (tx) => {
      let tenant = await prisma.tenant.findFirst({ where: { slug: "system" } });
      if (!tenant) {
        tenant = await prisma.tenant.create({
          data: {
            name: "System Tenant",
            slug: "system",
            plan: "enterprise",
            status: "ACTIVE",
          },
        });
      }
      await tx.$executeRaw`SELECT set_config('app.current_tenant_id', ${tenant.id}, true)`;

      let demoUser = await tx.user.findFirst({
        where: { tenantId: tenant.id, email: target.email },
      });

      if (!demoUser) {
        const mockPasswordHash = await hashPassword("DemoUser!2345");
        demoUser = await tx.user.create({
          data: {
            tenantId: tenant.id,
            email: target.email,
            passwordHash: mockPasswordHash,
            passwordChangedAt: new Date(),
            firstName: target.firstName,
            lastName: target.lastName,
            status: "ACTIVE",
          },
        });
      }

      let role = await tx.role.findFirst({
        where: { tenantId: tenant.id, name: target.roleName },
      });
      if (!role) {
        role = await tx.role.create({
          data: {
            tenantId: tenant.id,
            name: target.roleName,
            description: `Seeded ${target.roleName} role`,
            isSystem: true,
            permissions: JSON.stringify(["*"]),
          },
        });
      }

      const userRole = await tx.userRole.findFirst({
        where: { userId: demoUser.id, roleId: role.id },
      });
      if (!userRole) {
        await tx.userRole.create({
          data: { userId: demoUser.id, roleId: role.id },
        });
      }

      return demoUser;
    });

    return this.issueSession(user);
  }

  /**
   * Begins TOTP MFA setup: generates a base32 secret and a locally-rendered QR
   * code. The secret is stored as pending until a code is verified.
   */
  async generateMfaSecret(userId: string) {
    const user = await idpPrisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new BadRequestException("User not found.");
    }

    const secret = generateTotpSecret();

    await idpPrisma.user.update({
      where: { id: userId },
      data: { mfaSecret: encryptSecret(secret), mfaPending: true },
    });

    const { otpauthUrl, qrDataUrl } = await buildTotpEnrollment(
      user.email,
      secret,
    );

    return { secret, otpauthUrl, qrCodeUrl: qrDataUrl };
  }

  /**
   * Verifies a TOTP code and enables or disables MFA. Enabling returns one-time
   * recovery codes (shown once); disabling clears the secret and codes.
   */
  async verifyMfaAndEnable(userId: string, code: string, enable: boolean) {
    const user = await idpPrisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.mfaSecret) {
      throw new BadRequestException(
        "MFA has not been configured for this user.",
      );
    }

    if (!verifyTotp(code, decryptSecret(user.mfaSecret))) {
      throw new BadRequestException("Invalid verification code.");
    }

    if (!enable) {
      await idpPrisma.user.update({
        where: { id: userId },
        data: {
          mfaEnabled: false,
          mfaPending: false,
          mfaSecret: null,
          mfaRecoveryCodes: [],
        },
      });
      return { message: "MFA disabled successfully." };
    }

    const { plain, hashes } = await generateRecoveryCodes();
    await idpPrisma.user.update({
      where: { id: userId },
      data: { mfaEnabled: true, mfaPending: false, mfaRecoveryCodes: hashes },
    });

    return {
      message: "MFA enabled successfully.",
      recoveryCodes: plain,
    };
  }

  /**
   * Completes an MFA login: validates the challenge token from step one, then
   * the TOTP code (or a single-use recovery code), and issues a session.
   */
  async verifyMfaLogin(
    challengeToken: string,
    code: string,
    context?: SessionContext,
  ) {
    const payload = verifyTypedToken<{ userId: string }>(
      challengeToken,
      TOKEN_TYPE.MFA_CHALLENGE,
    );
    if (!payload?.userId) {
      throw new UnauthorizedException(
        "MFA session expired. Please sign in again.",
      );
    }

    const user = await idpPrisma.user.findUnique({
      where: { id: payload.userId },
    });

    if (!user || !user.mfaEnabled || !user.mfaSecret) {
      throw new BadRequestException("MFA is not configured for this user.");
    }

    const totpOk = verifyTotp(code, decryptSecret(user.mfaSecret));

    if (!totpOk) {
      // Fall back to single-use recovery codes.
      const storedCodes = Array.isArray(user.mfaRecoveryCodes)
        ? (user.mfaRecoveryCodes as string[])
        : [];
      const matchIndex = await matchRecoveryCode(code, storedCodes);
      if (matchIndex === -1) {
        await this.recordFailedLogin(
          user.id,
          user.tenantId,
          "MFA_VERIFICATION_FAILED",
          context,
        );
        throw new UnauthorizedException("Invalid verification code.");
      }
      // Consume the used recovery code.
      const remaining = storedCodes.filter((_, i) => i !== matchIndex);
      await idpPrisma.user.update({
        where: { id: user.id },
        data: { mfaRecoveryCodes: remaining },
      });
    }

    return this.issueSession(user, context);
  }

  /**
   * Marks a session inactive so its token is rejected on the next request.
   * Idempotent — unknown or already-revoked ids are a no-op.
   */
  async revokeSessionById(sid: string) {
    if (!sid) return;
    await idpPrisma.userSession.updateMany({
      where: { id: sid, isActive: true },
      // Clearing the refresh hash kills silent renewal along with the session.
      data: { isActive: false, refreshTokenHash: null },
    });
  }

  /** Active sessions for the "Active Sessions" profile UI, most-recent first. */
  async listSessions(userId: string, tenantId: string, currentSid?: string) {
    const sessions = await idpPrisma.userSession.findMany({
      where: { userId, tenantId, isActive: true },
      orderBy: { lastActivityAt: "desc" },
    });
    return sessions.map((s) => ({
      id: s.id,
      device: s.device,
      browser: s.browser,
      ipAddress: s.ipAddress,
      location: s.location,
      startedAt: s.startedAt,
      lastActivityAt: s.lastActivityAt,
      isCurrent: s.id === currentSid,
      deviceId: s.deviceId,
      platform: s.platform,
      appVersion: s.appVersion,
    }));
  }

  /** Revokes every session for this user except the one making the request. */
  async revokeOtherSessions(
    userId: string,
    tenantId: string,
    currentSid?: string,
  ) {
    const result = await idpPrisma.userSession.updateMany({
      where: {
        userId,
        tenantId,
        isActive: true,
        ...(currentSid ? { id: { not: currentSid } } : {}),
      },
      data: { isActive: false },
    });
    return { revoked: result.count };
  }

  /**
   * Revokes one specific session belonging to the calling user — the
   * "log out this device" action (.ai/MULTI_CLIENT_MASTER_PLAN.md § 7).
   * Ownership-scoped by userId+tenantId so a session id alone is never
   * enough to revoke someone else's session.
   */
  async revokeOwnSessionById(userId: string, tenantId: string, sid: string) {
    const result = await idpPrisma.userSession.updateMany({
      where: { id: sid, userId, tenantId, isActive: true },
      data: { isActive: false, refreshTokenHash: null },
    });
    if (result.count === 0) {
      throw new NotFoundException("Session not found.");
    }
    return { revoked: true };
  }

  /* ─────────────────────────────────────────────────────────
     Email OTP — real-time verification during registration
     ───────────────────────────────────────────────────────── */

  /** In-memory OTP store. In production, use Redis with a TTL. */
  private readonly otpStore = new Map<
    string,
    { code: string; expiresAt: number; attempts: number }
  >();

  private generateOtp(): string {
    return String(randomInt(100000, 1000000));
  }

  async sendOtp(
    email: string,
  ): Promise<{ message: string; cooldownSeconds: number }> {
    const normalized = email.toLowerCase().trim();
    const existing = this.otpStore.get(normalized);

    // Rate-limit: 60s cooldown per email
    if (existing) {
      const elapsed = Date.now() - (existing.expiresAt - 5 * 60 * 1000);
      if (elapsed < 60000 && existing.attempts > 0) {
        const remaining = Math.ceil((60000 - elapsed) / 1000);
        return {
          message: `Please wait ${remaining}s before requesting a new code.`,
          cooldownSeconds: remaining,
        };
      }
    }

    const code = this.generateOtp();
    this.otpStore.set(normalized, {
      code,
      expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes
      attempts: 0,
    });

    await this.dispatchAuthEmail({
      to: normalized,
      tenantId: "",
      subject: "Your UniERP verification code",
      body: `Your verification code is: ${code}\n\nThis code expires in 5 minutes.\n\nIf you did not request this, please ignore this email.`,
    });

    this.logger.log(`[OTP] Code ${code} sent to ${normalized}`);
    return {
      message: "Verification code sent to your email.",
      cooldownSeconds: 60,
    };
  }

  async verifyOtp(
    email: string,
    code: string,
  ): Promise<{ verified: boolean; message: string }> {
    const normalized = email.toLowerCase().trim();
    const record = this.otpStore.get(normalized);

    if (!record) {
      return {
        verified: false,
        message: "No verification code found. Request a new one.",
      };
    }

    if (Date.now() > record.expiresAt) {
      this.otpStore.delete(normalized);
      return {
        verified: false,
        message: "Verification code has expired. Request a new one.",
      };
    }

    record.attempts += 1;
    if (record.attempts > 5) {
      this.otpStore.delete(normalized);
      return {
        verified: false,
        message: "Too many failed attempts. Request a new code.",
      };
    }

    if (record.code !== code.trim()) {
      return {
        verified: false,
        message: "Invalid verification code. Please try again.",
      };
    }

    this.otpStore.delete(normalized);
    return { verified: true, message: "Email verified successfully." };
  }

  async getOnboardingStatus(
    tenantId: string,
    userId: string,
  ): Promise<{ completed: boolean; steps: string[] }> {
    try {
      const tenant = await prisma.tenant.findUnique({
        where: { id: tenantId },
      });
      if (!tenant) return { completed: false, steps: [] };
      const settings = (tenant.settings as Record<string, any>) || {};
      const checklist =
        (settings.onboardingChecklist as Record<string, boolean>) || {};

      const user = await idpPrisma.user.findFirst({
        where: { id: userId, tenantId },
        select: { avatar: true },
      });
      const logoUrl = settings.logoUrl;
      const inviteCount = await idpPrisma.user.count({
        where: {
          tenantId,
          id: { not: userId },
          status: { in: ["INVITED", "ACTIVE"] },
        },
      });
      const marketplaceAppCount = await prisma.installedApp.count({
        where: { tenantId, source: "MARKETPLACE" },
      });
      const subscription = await prisma.tenantSubscription.findUnique({
        where: { tenantId },
        include: { plan: true },
      });

      const profileDone = Boolean(user?.avatar);
      const logoDone = typeof logoUrl === "string" && logoUrl.trim().length > 0;
      const inviteDone = inviteCount > 0;
      const appDone = marketplaceAppCount > 0;
      const planName = subscription?.plan?.name?.toLowerCase();
      const planDone = Boolean(
        subscription && planName && planName !== "free" && planName !== "trial",
      );
      const dashboardDone = Boolean(checklist.dashboard);

      const mandatoryKeys = ["profile", "logo", "app"] as const;
      const steps: Record<string, boolean> = {
        profile: profileDone,
        logo: logoDone,
        invite: inviteDone,
        app: appDone,
        plan: planDone,
        dashboard: dashboardDone,
      };
      const incomplete = mandatoryKeys.filter((k) => !steps[k]);

      return { completed: incomplete.length === 0, steps: incomplete };
    } catch {
      return { completed: false, steps: [] };
    }
  }

  /** Stores a small avatar image as a data URI on the user record. */
  async updateAvatar(userId: string, dataUri: string) {
    const updated = await idpPrisma.user.update({
      where: { id: userId },
      data: { avatar: dataUri },
    });
    return { avatar: updated.avatar };
  }

  /* ─────────────────────────────────────────────────────────
     MFA push-approval (Web Push) — an "Approve on your phone"
     alternative to typing a 6-digit code every login. The code
     entry path always keeps working; push is a convenience.
     ───────────────────────────────────────────────────────── */

  /** Registers a device (browser/PWA) to receive push-approval prompts. */
  async subscribeToPush(
    userId: string,
    tenantId: string,
    sub: { endpoint: string; keys: { p256dh: string; auth: string } },
    label?: string,
  ) {
    return runWithTenantSession({ tenantId, userId }, () =>
      idpPrisma.pushSubscription.upsert({
        where: { endpoint: sub.endpoint },
        create: {
          tenantId,
          userId,
          endpoint: sub.endpoint,
          p256dh: sub.keys.p256dh,
          auth: sub.keys.auth,
          label: label ?? null,
        },
        update: {
          p256dh: sub.keys.p256dh,
          auth: sub.keys.auth,
          label: label ?? null,
        },
      }),
    );
  }

  async unsubscribeFromPush(
    userId: string,
    tenantId: string,
    endpoint: string,
  ) {
    await runWithTenantSession({ tenantId, userId }, () =>
      idpPrisma.pushSubscription.deleteMany({
        where: { userId, tenantId, endpoint },
      }),
    );
    return { message: "Device removed." };
  }

  /** Removes any of the user's registered push devices by id (profile "Devices" list). */
  async removePushDeviceById(userId: string, tenantId: string, id: string) {
    await runWithTenantSession({ tenantId, userId }, () =>
      idpPrisma.pushSubscription.deleteMany({
        where: { userId, tenantId, id },
      }),
    );
    return { message: "Device removed." };
  }

  async listPushSubscriptions(userId: string, tenantId: string) {
    return runWithTenantSession({ tenantId, userId }, () =>
      idpPrisma.pushSubscription.findMany({
        where: { userId, tenantId },
        orderBy: { createdAt: "desc" },
        select: { id: true, label: true, createdAt: true },
      }),
    );
  }

  /**
   * Fires an "Approve this sign-in?" push to every device the user has
   * registered. Returns whether anything was actually sent — the login
   * page uses this to decide whether to lead with "check your phone" or
   * go straight to the manual-code form.
   */
  private async sendMfaPushChallenge(
    challengeToken: string,
    userId: string,
    tenantId: string,
  ): Promise<boolean> {
    if (!(await this.configureWebPush())) return false;

    return runWithTenantSession({ tenantId, userId }, async () => {
      const subscriptions = await idpPrisma.pushSubscription.findMany({
        where: { userId, tenantId },
      });
      if (subscriptions.length === 0) return false;

      await idpPrisma.mfaPushChallenge.create({
        data: {
          tenantId,
          userId,
          token: hashChallengeToken(challengeToken),
          status: "PENDING",
          expiresAt: new Date(Date.now() + MFA_PUSH_TTL_MS),
        },
      });

      const payload = JSON.stringify({
        type: "mfa-approval",
        title: "Approve sign-in?",
        body: "Someone is signing in to your UniERP account. Tap to approve or deny.",
        challengeToken,
      });

      const results = await Promise.allSettled(
        subscriptions.map((s) =>
          webPush.sendNotification(
            { endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } },
            payload,
          ),
        ),
      );

      // A 404/410 means the browser unregistered that endpoint — stop targeting it.
      await Promise.all(
        results.map((r, i) => {
          if (r.status !== "rejected") return Promise.resolve();
          const statusCode = (r.reason as { statusCode?: number })?.statusCode;
          if (statusCode !== 404 && statusCode !== 410) {
            this.logger.warn(`MFA push delivery failed: ${r.reason}`);
            return Promise.resolve();
          }
          const sub = subscriptions[i];
          if (!sub) return Promise.resolve();
          return idpPrisma.pushSubscription
            .delete({ where: { id: sub.id } })
            .catch(() => undefined);
        }),
      );

      return true;
    });
  }

  /**
   * Polled by the login page while "Check your phone" is showing. Once
   * approved, finalizes the login exactly like a correct 6-digit code would.
   */
  async getMfaPushStatus(challengeToken: string, context?: SessionContext) {
    const payload = verifyTypedToken<{ userId: string; tenantId: string }>(
      challengeToken,
      TOKEN_TYPE.MFA_CHALLENGE,
    );
    if (!payload?.userId) {
      throw new UnauthorizedException(
        "MFA session expired. Please sign in again.",
      );
    }

    return runWithTenantSession(
      { tenantId: payload.tenantId, userId: payload.userId },
      async () => {
        const challenge = await idpPrisma.mfaPushChallenge.findUnique({
          where: { token: hashChallengeToken(challengeToken) },
        });
        if (!challenge) return { status: "not_sent" as const };

        if (
          challenge.status === "PENDING" &&
          challenge.expiresAt < new Date()
        ) {
          await idpPrisma.mfaPushChallenge.update({
            where: { id: challenge.id },
            data: { status: "EXPIRED" },
          });
          return { status: "expired" as const };
        }

        if (challenge.status === "DENIED") {
          await this.recordFailedLogin(
            payload.userId,
            payload.tenantId,
            "MFA_PUSH_DENIED",
            context,
          );
          return { status: "denied" as const };
        }
        if (challenge.status === "EXPIRED") {
          await this.recordFailedLogin(
            payload.userId,
            payload.tenantId,
            "MFA_PUSH_EXPIRED",
            context,
          );
          return { status: "expired" as const };
        }
        if (challenge.status !== "APPROVED")
          return { status: "pending" as const };

        const user = await idpPrisma.user.findUnique({
          where: { id: payload.userId },
        });
        if (!user) throw new UnauthorizedException("Account no longer exists.");

        const session = await this.issueSession(user, context);
        return { status: "approved" as const, ...session };
      },
    );
  }

  /**
   * Called from the device that *received* the push (already has its own
   * valid session) to approve or deny somebody else's pending login.
   */
  async respondToMfaPushChallenge(
    approvingUserId: string,
    approvingTenantId: string,
    challengeToken: string,
    approve: boolean,
  ) {
    const payload = verifyTypedToken<{ userId: string; tenantId: string }>(
      challengeToken,
      TOKEN_TYPE.MFA_CHALLENGE,
    );
    if (
      !payload?.userId ||
      payload.userId !== approvingUserId ||
      payload.tenantId !== approvingTenantId
    ) {
      throw new UnauthorizedException(
        "This approval request does not belong to you.",
      );
    }

    return runWithTenantSession(
      { tenantId: approvingTenantId, userId: approvingUserId },
      async () => {
        const challenge = await idpPrisma.mfaPushChallenge.findUnique({
          where: { token: hashChallengeToken(challengeToken) },
        });
        if (
          !challenge ||
          challenge.status !== "PENDING" ||
          challenge.expiresAt < new Date()
        ) {
          throw new BadRequestException("This approval request has expired.");
        }
        await idpPrisma.mfaPushChallenge.update({
          where: { id: challenge.id },
          data: { status: approve ? "APPROVED" : "DENIED" },
        });
        return { message: approve ? "Sign-in approved." : "Sign-in denied." };
      },
    );
  }
}
