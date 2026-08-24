import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from "@nestjs/common";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { idpPrisma, prisma, runWithTenantSession } from "@kannan19302/database";
import { getWebAuthnConfig } from "../../common/webauthn/webauthn.config";
import { emitAuthAudit } from "../../common/audit/emit-auth-audit";
import { AuthService, type SessionContext } from "./auth.service";
import { ExternalAuthStore } from "./external-auth.store";

const MAX_PASSKEYS = 10;
const RECENT_AUTH_MS = 10 * 60 * 1000;
const CREDENTIAL_ID = /^[A-Za-z0-9_-]{16,2048}$/;

type PasskeyLookup = {
  id: string;
  tenant_id: string;
  user_id: string;
  credential_id: string;
  public_key: string;
  counter: bigint;
  transports: string | null;
  device_type: string | null;
  backup_eligible: boolean;
  backed_up: boolean;
};

@Injectable()
export class PasskeyService {
  constructor(
    private readonly auth: AuthService,
    private readonly store: ExternalAuthStore,
  ) {}

  async registrationOptions(userId: string, tenantId: string, sid: string) {
    await this.requireFreshSession(userId, tenantId, sid);
    const config = getWebAuthnConfig();
    const { user, passkeys } = await runWithTenantSession(
      { tenantId, userId },
      async () => {
        const [user, passkeys] = await Promise.all([
          idpPrisma.user.findUnique({ where: { id: userId } }),
          idpPrisma.passkey.findMany({
            where: { userId },
            select: { credentialId: true, transports: true },
          }),
        ]);
        return { user, passkeys };
      },
    );
    if (!user || user.status !== "ACTIVE") {
      throw new UnauthorizedException("Active account required.");
    }
    if (passkeys.length >= MAX_PASSKEYS) {
      throw new BadRequestException(`A maximum of ${MAX_PASSKEYS} passkeys is allowed.`);
    }

    const options = await generateRegistrationOptions({
      rpName: config.rpName,
      rpID: config.rpId,
      userID: new TextEncoder().encode(user.id),
      userName: user.email,
      userDisplayName: `${user.firstName} ${user.lastName}`.trim() || user.email,
      attestationType: "none",
      excludeCredentials: passkeys.map((passkey) => ({
        id: passkey.credentialId,
        transports: parseTransports(passkey.transports),
      })),
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required",
      },
      supportedAlgorithmIDs: [-7, -257],
      timeout: 60_000,
    });
    const handle = await this.store.createPasskeyCeremony({
      purpose: "registration",
      challenge: options.challenge,
      rpId: config.rpId,
      expectedOrigins: config.expectedOrigins,
      userId,
      tenantId,
    });
    return { handle, options };
  }

  async verifyRegistration(params: {
    userId: string;
    tenantId: string;
    sid: string;
    handle: string;
    name?: string;
    response: RegistrationResponseJSON;
  }) {
    await this.requireFreshSession(params.userId, params.tenantId, params.sid);
    const ceremony = await this.store.consumePasskeyCeremony(params.handle);
    if (
      !ceremony ||
      ceremony.purpose !== "registration" ||
      ceremony.userId !== params.userId ||
      ceremony.tenantId !== params.tenantId
    ) {
      throw new BadRequestException("Passkey ceremony expired or was already used.");
    }

    const verification = await verifyRegistrationResponse({
      response: params.response,
      expectedChallenge: ceremony.challenge,
      expectedOrigin: ceremony.expectedOrigins,
      expectedRPID: ceremony.rpId,
      requireUserPresence: true,
      requireUserVerification: true,
      supportedAlgorithmIDs: [-7, -257],
    }).catch(() => {
      throw new UnauthorizedException("Passkey verification failed.");
    });
    if (!verification.verified || !verification.registrationInfo?.userVerified) {
      throw new UnauthorizedException("Passkey verification failed.");
    }

    const info = verification.registrationInfo;
    const name = sanitizeName(params.name);
    const created = await runWithTenantSession(
      { tenantId: params.tenantId, userId: params.userId },
      () => idpPrisma.passkey.create({
        data: {
          tenantId: params.tenantId,
          userId: params.userId,
          credentialId: info.credential.id,
          publicKey: Buffer.from(info.credential.publicKey).toString("base64url"),
          counter: BigInt(info.credential.counter),
          transports: serializeTransports(info.credential.transports),
          name,
          deviceType: info.credentialDeviceType,
          backupEligible: info.credentialDeviceType === "multiDevice",
          backedUp: info.credentialBackedUp,
          aaguid: info.aaguid,
        },
        select: {
          id: true,
          name: true,
          deviceType: true,
          backedUp: true,
          createdAt: true,
        },
      }),
    ).catch((error: unknown) => {
      if (isUniqueConstraint(error)) {
        throw new BadRequestException("This passkey is already registered.");
      }
      throw error;
    });
    await emitAuthAudit({
      tenantId: params.tenantId,
      userId: params.userId,
      action: "PASSKEY_REGISTERED",
      entityType: "Passkey",
      entityId: created.id,
      changes: { name: created.name, deviceType: created.deviceType, backedUp: created.backedUp },
    });
    return created;
  }

  async authenticationOptions(returnTo: string) {
    const config = getWebAuthnConfig();
    const options = await generateAuthenticationOptions({
      rpID: config.rpId,
      userVerification: "required",
      timeout: 60_000,
    });
    const handle = await this.store.createPasskeyCeremony({
      purpose: "authentication",
      challenge: options.challenge,
      rpId: config.rpId,
      expectedOrigins: config.expectedOrigins,
      returnTo,
    });
    return { handle, options };
  }

  async verifyAuthentication(params: {
    handle: string;
    response: AuthenticationResponseJSON;
    context?: SessionContext;
  }) {
    const ceremony = await this.store.consumePasskeyCeremony(params.handle);
    if (!ceremony || ceremony.purpose !== "authentication") {
      throw new BadRequestException("Passkey ceremony expired or was already used.");
    }
    if (!CREDENTIAL_ID.test(params.response.id)) {
      throw new UnauthorizedException("Passkey verification failed.");
    }

    const rows = await prisma.$queryRaw<PasskeyLookup[]>`
      SELECT * FROM auth_lookup_passkey(${params.response.id})
    `;
    const passkey = rows[0];
    if (!passkey) throw new UnauthorizedException("Passkey verification failed.");

    const currentCounter = Number(passkey.counter);
    if (!Number.isSafeInteger(currentCounter) || currentCounter < 0) {
      throw new UnauthorizedException("Passkey counter is invalid.");
    }
    const verification = await verifyAuthenticationResponse({
      response: params.response,
      expectedChallenge: ceremony.challenge,
      expectedOrigin: ceremony.expectedOrigins,
      expectedRPID: ceremony.rpId,
      requireUserVerification: true,
      credential: {
        id: passkey.credential_id,
        publicKey: new Uint8Array(Buffer.from(passkey.public_key, "base64url")),
        counter: currentCounter,
        transports: parseTransports(passkey.transports),
      },
    }).catch(() => {
      throw new UnauthorizedException("Passkey verification failed.");
    });
    if (!verification.verified || !verification.authenticationInfo.userVerified) {
      throw new UnauthorizedException("Passkey verification failed.");
    }

    const { user, updated } = await runWithTenantSession(
      { tenantId: passkey.tenant_id, userId: passkey.user_id },
      async () => {
        const user = await idpPrisma.user.findFirst({
          where: { id: passkey.user_id, status: "ACTIVE", deletedAt: null },
        });
        const updated = await idpPrisma.passkey.updateMany({
          where: { id: passkey.id, userId: passkey.user_id, counter: passkey.counter },
          data: {
            counter: BigInt(verification.authenticationInfo.newCounter),
            deviceType: verification.authenticationInfo.credentialDeviceType,
            backedUp: verification.authenticationInfo.credentialBackedUp,
            lastUsedAt: new Date(),
          },
        });
        return { user, updated };
      },
    );
    if (!user || updated.count !== 1) {
      throw new UnauthorizedException("Passkey state changed; try again.");
    }

    const session = await this.auth.issueSession(
      { ...user, authMethods: [{ type: "WEBAUTHN" }] },
      params.context,
      { mfaVerified: true },
    );
    await emitAuthAudit({
      tenantId: passkey.tenant_id,
      userId: passkey.user_id,
      action: "PASSKEY_AUTHENTICATED",
      entityType: "Passkey",
      entityId: passkey.id,
      changes: {
        deviceType: verification.authenticationInfo.credentialDeviceType,
        backedUp: verification.authenticationInfo.credentialBackedUp,
      },
    });
    return { ...session, returnTo: ceremony.returnTo || "/" };
  }

  async deletePasskey(params: {
    userId: string;
    tenantId: string;
    sid: string;
    passkeyId: string;
  }): Promise<void> {
    await this.requireFreshSession(params.userId, params.tenantId, params.sid);
    await runWithTenantSession(
      { tenantId: params.tenantId, userId: params.userId },
      async () => {
        const [user, passkeyCount, identityCount] = await Promise.all([
          idpPrisma.user.findUnique({ where: { id: params.userId } }),
          idpPrisma.passkey.count({ where: { userId: params.userId } }),
          idpPrisma.userIdentity.count({ where: { userId: params.userId } }),
        ]);
        if (!user) throw new UnauthorizedException("Account not found.");
        if (!user.passwordHash && identityCount === 0 && passkeyCount <= 1) {
          throw new BadRequestException("Add another sign-in method before removing your last passkey.");
        }
        const deleted = await idpPrisma.passkey.deleteMany({
          where: { id: params.passkeyId, userId: params.userId },
        });
        if (deleted.count !== 1) throw new BadRequestException("Passkey not found.");
        await idpPrisma.userSession.updateMany({
          where: { userId: params.userId, id: { not: params.sid }, isActive: true },
          data: { isActive: false },
        });
      },
    );
    await emitAuthAudit({
      tenantId: params.tenantId,
      userId: params.userId,
      action: "PASSKEY_REMOVED",
      entityType: "Passkey",
      entityId: params.passkeyId,
    });
  }

  private async requireFreshSession(userId: string, tenantId: string, sid: string) {
    const session = await runWithTenantSession({ tenantId, userId }, () =>
      idpPrisma.userSession.findUnique({ where: { id: sid } }),
    );
    if (
      !session ||
      !session.isActive ||
      session.userId !== userId ||
      session.tenantId !== tenantId ||
      session.startedAt.getTime() < Date.now() - RECENT_AUTH_MS
    ) {
      throw new UnauthorizedException("Recent authentication is required to change passkeys.");
    }
  }
}

function parseTransports(value?: string | null): AuthenticatorTransportFuture[] | undefined {
  if (!value) return undefined;
  const allowed = new Set<AuthenticatorTransportFuture>([
    "ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb",
  ]);
  const parsed = value.split(",").map((item) => item.trim())
    .filter((item): item is AuthenticatorTransportFuture => allowed.has(item as AuthenticatorTransportFuture));
  return parsed.length ? parsed : undefined;
}

function serializeTransports(value?: AuthenticatorTransportFuture[]): string | null {
  return value?.length ? Array.from(new Set(value)).join(",") : null;
}

function sanitizeName(value?: string): string {
  const name = value?.trim().replace(/\s+/g, " ") || "My passkey";
  if (name.length > 60) throw new BadRequestException("Passkey name must be 60 characters or fewer.");
  return name;
}

function isUniqueConstraint(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "P2002";
}
