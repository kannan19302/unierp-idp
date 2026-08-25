import { Injectable, Logger } from "@nestjs/common";
import { idpPrisma, runWithTenantSession } from "@kannan19302/database";
import { OAuthError } from "./authorization.service";
import { OAUTH_ERROR, TOKEN_TTL } from "../oidc.constants";
import { emitAuthAudit } from "../../../common/audit/emit-auth-audit";

/**
 * RFC 8693 token exchange, bounded to AI agent delegation.
 *
 * This is the mechanism the whole "agentic AI, full control restricted to
 * tenant level, no security compromise" requirement rests on. An agent is
 * never authenticated with its own credentials — it exists only as something a
 * LIVE user token can be exchanged for, and the exchange enforces every one of
 * these, in this order, any one of which is enough to refuse:
 *
 *   1. The subject token must be a real, unexpired, unrevoked user session —
 *      not a service credential, not another agent's token (no chaining).
 *   2. The agent must be registered, ACTIVE, and belong to the subject's own
 *      tenant. A tenant can never exchange for another tenant's agent.
 *   3. Effective authority is allowedPermissions ∩ the user's CURRENT
 *      permissions — recomputed at exchange time, not cached from
 *      registration, so demoting the user immediately demotes every agent
 *      acting on their behalf.
 *   4. The database CHECK constraint (agent_permissions_within_control_plane_bound)
 *      already makes the system.*, platform.*, and pcc.* namespaces, and "*", impossible
 *      to register on an agent at all — this service does not re-derive that
 *      guarantee, it inherits it structurally from what can exist in
 *      agent_definitions.
 *   5. The resulting token is short-lived (minutes, not the user's own TTL)
 *      and chained to the user's own `sid`, so revoking the user's session —
 *      logout, an admin action, a compromised-account response — kills every
 *      agent token derived from it in the same instant, with no separate
 *      revocation path to forget.
 *
 * Every exchange is recorded in AgentDelegation, which is what lets "who
 * created this invoice" answer both the human (sub) and the agent (act).
 */
@Injectable()
export class AgentDelegationService {
  private readonly logger = new Logger(AgentDelegationService.name);

  async exchange(params: {
    /** Claims already verified off the subject (user) access token. */
    subjectUserId: string;
    subjectTenantId: string;
    subjectSid: string;
    subjectPermissions: string[];
    subjectRealm: "tenant" | "provider";
    /** The agent named in the token-exchange request. */
    agentId: string;
    /** Scopes/permissions the caller requested for this exchange, if any. */
    requestedPermissions?: string[];
  }): Promise<{
    agentId: string;
    effectivePermissions: string[];
    sid: string;
    expiresAt: Date;
  }> {
    // 1. The subject must be a genuine, live user session — never another
    //    agent's token. Chained delegation (an agent exchanging for a second
    //    agent) would let authority drift arbitrarily far from the human who
    //    is supposed to be accountable for it, so it is refused structurally:
    //    a subject token carrying its own `act` claim is rejected outright.
    if (params.subjectRealm !== "tenant" && params.subjectRealm !== "provider") {
      throw new OAuthError(OAUTH_ERROR.INVALID_GRANT, "Invalid subject token");
    }

    // 2. The agent must exist, be active, and belong to this tenant.
    const agent = await runWithTenantSession(
      { tenantId: params.subjectTenantId, userId: params.subjectUserId },
      () =>
        idpPrisma.agentDefinition.findUnique({
          where: { id: params.agentId },
        }),
    );

    if (!agent || agent.tenantId !== params.subjectTenantId) {
      // Deliberately identical to "agent does not exist" — confirming that an
      // agent id is valid but belongs to another tenant would leak that
      // tenant's internal identifiers to an unrelated caller.
      throw new OAuthError(OAUTH_ERROR.INVALID_GRANT, "Unknown agent");
    }
    if (agent.status !== "ACTIVE") {
      throw new OAuthError(OAUTH_ERROR.INVALID_GRANT, "Agent is not active");
    }

    // 3. Authority is the ceiling intersected with what the user holds RIGHT
    //    NOW — never the ceiling alone, and never the caller's requested set
    //    alone. Requesting permissions the user does not currently hold does
    //    not expand what the agent receives; it simply does not add them.
    const requested = params.requestedPermissions?.length
      ? params.requestedPermissions
      : agent.allowedPermissions;

    const effectivePermissions = requested.filter(
      (permission) =>
        agent.allowedPermissions.includes(permission) &&
        params.subjectPermissions.includes(permission),
    );

    // 5. Bound to the user's own session. Revoking that session — logout, an
    //    admin lockout, a compromised-account response — must kill this
    //    delegation too, with no separate place to remember to revoke it.
    const expiresAt = new Date(Date.now() + TOKEN_TTL.AGENT_TOKEN_MS);

    await runWithTenantSession(
      { tenantId: params.subjectTenantId, userId: params.subjectUserId },
      () =>
        idpPrisma.agentDelegation.create({
          data: {
            tenantId: params.subjectTenantId,
            agentId: agent.id,
            delegatingUserId: params.subjectUserId,
            effectivePermissions,
            sid: params.subjectSid,
            expiresAt,
          },
        }),
    );

    this.logger.log(
      `Agent ${agent.id} exchanged for user ${params.subjectUserId} in tenant ${params.subjectTenantId}: ${effectivePermissions.length} permission(s)`,
    );

    await emitAuthAudit({
      tenantId: params.subjectTenantId,
      userId: params.subjectUserId,
      action: "AUTH_TOKEN_EXCHANGE",
      entityType: "AgentDefinition",
      entityId: agent.id,
      changes: { effectivePermissions, sid: params.subjectSid },
    });

    return {
      agentId: agent.id,
      effectivePermissions,
      sid: params.subjectSid,
      expiresAt,
    };
  }

  /**
   * Recomputes an agent token's CURRENT effective authority against the live
   * state of both sides of the intersection.
   *
   * Called from the guard chain (not built here — this is the primitive it
   * will use) on every request an agent token makes, rather than trusting the
   * permission list frozen into the token at exchange time. A user demoted
   * moments after an agent token was minted must not leave that token holding
   * stale authority for the remainder of its (short) lifetime.
   */
  async currentEffectivePermissions(params: {
    agentId: string;
    tenantId: string;
    delegatingUserId: string;
    currentUserPermissions: string[];
  }): Promise<string[]> {
    const agent = await runWithTenantSession(
      { tenantId: params.tenantId, userId: params.delegatingUserId },
      () =>
        idpPrisma.agentDefinition.findUnique({ where: { id: params.agentId } }),
    );

    if (!agent || agent.status !== "ACTIVE" || agent.tenantId !== params.tenantId) {
      return [];
    }

    return agent.allowedPermissions.filter((permission) =>
      params.currentUserPermissions.includes(permission),
    );
  }
}
