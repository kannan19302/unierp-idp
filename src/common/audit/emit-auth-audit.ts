import { prisma, runWithTenantSession } from "@kannan19302/database";

/**
 * Central AuditLog emitter for authentication-domain events — the ones the
 * plan lists explicitly (tenant switch, platform entry, consent grant/revoke,
 * token exchange, impersonation, permission denial) that are not already
 * captured by `LoginHistory` (which owns login/failure/lockout/MFA at finer
 * granularity, with its own schema for that).
 *
 * `AuditLog.userId` is NOT NULL in the schema, so denial/system events that
 * have no authenticated actor (e.g. a request that never reached a session)
 * are not routed through this helper — there is nothing meaningful to write.
 *
 * Best-effort: a failure to write an audit row must never fail the request
 * whose action it is describing.
 */
export async function emitAuthAudit(params: {
  tenantId: string;
  userId: string;
  action: string;
  entityType: string;
  entityId: string;
  changes?: Record<string, unknown>;
  ipAddress?: string;
}): Promise<void> {
  await runWithTenantSession(
    { tenantId: params.tenantId, userId: params.userId },
    () =>
      prisma.auditLog.create({
        data: {
          tenantId: params.tenantId,
          userId: params.userId,
          action: params.action,
          entityType: params.entityType,
          entityId: params.entityId,
          changes: (params.changes as any) ?? undefined,
          ipAddress: params.ipAddress ?? null,
        },
      }),
  );
}
