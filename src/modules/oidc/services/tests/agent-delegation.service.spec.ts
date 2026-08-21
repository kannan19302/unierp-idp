import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@kannan19302/database", () => ({
  idpPrisma: {
    agentDefinition: { findUnique: vi.fn() },
    agentDelegation: { create: vi.fn() },
  },
  prisma: {},
  runWithTenantSession: vi.fn((_s: unknown, fn: () => unknown) => fn()),
}));

import { idpPrisma } from "@kannan19302/database";
import { AgentDelegationService } from "../agent-delegation.service";
import { OAuthError } from "../authorization.service";

function agent(over: Record<string, unknown> = {}) {
  return {
    id: "agent-1",
    tenantId: "t1",
    name: "Invoice Agent",
    allowedPermissions: ["finance.invoice.read", "finance.invoice.create"],
    status: "ACTIVE",
    ...over,
  };
}

const baseSubject = {
  subjectUserId: "u1",
  subjectTenantId: "t1",
  subjectSid: "sess-1",
  subjectPermissions: [
    "finance.invoice.read",
    "finance.invoice.create",
    "hr.employee.read",
  ],
  subjectRealm: "tenant" as const,
  agentId: "agent-1",
};

describe("AgentDelegationService", () => {
  let service: AgentDelegationService;

  beforeEach(() => {
    vi.clearAllMocks();
    service = new AgentDelegationService();
  });

  describe("exchange", () => {
    it("grants the intersection of the agent's ceiling and the user's current permissions", async () => {
      vi.mocked(idpPrisma.agentDefinition.findUnique).mockResolvedValue(
        agent() as never,
      );

      const grant = await service.exchange(baseSubject);

      // hr.employee.read is on the user but not the agent's ceiling; it must
      // not leak into what the agent receives.
      expect(grant.effectivePermissions.sort()).toEqual(
        ["finance.invoice.create", "finance.invoice.read"].sort(),
      );
    });

    it("never grants a permission the user does not currently hold, even if the agent's ceiling allows it", async () => {
      // The point of recomputing at exchange time rather than trusting a
      // cached grant: if the user was demoted since the agent was configured,
      // the agent must not inherit authority the user no longer has.
      vi.mocked(idpPrisma.agentDefinition.findUnique).mockResolvedValue(
        agent({
          allowedPermissions: ["finance.invoice.read", "finance.invoice.approve"],
        }) as never,
      );

      const grant = await service.exchange({
        ...baseSubject,
        subjectPermissions: ["finance.invoice.read"], // approve was revoked
      });

      expect(grant.effectivePermissions).toEqual(["finance.invoice.read"]);
    });

    it("never grants more than the agent's own ceiling, even if requested", async () => {
      vi.mocked(idpPrisma.agentDefinition.findUnique).mockResolvedValue(
        agent({ allowedPermissions: ["finance.invoice.read"] }) as never,
      );

      const grant = await service.exchange({
        ...baseSubject,
        requestedPermissions: [
          "finance.invoice.read",
          "finance.invoice.create", // beyond the agent's ceiling
        ],
      });

      expect(grant.effectivePermissions).toEqual(["finance.invoice.read"]);
    });

    it("refuses an unknown agent", async () => {
      vi.mocked(idpPrisma.agentDefinition.findUnique).mockResolvedValue(
        null as never,
      );

      await expect(service.exchange(baseSubject)).rejects.toThrow(OAuthError);
      expect(idpPrisma.agentDelegation.create).not.toHaveBeenCalled();
    });

    it("refuses an agent belonging to a different tenant, identically to an unknown one", async () => {
      // A tenant must never learn that an agent id is valid but belongs to
      // someone else — that alone would leak the other tenant's identifiers.
      vi.mocked(idpPrisma.agentDefinition.findUnique).mockResolvedValue(
        agent({ tenantId: "other-tenant" }) as never,
      );

      const err = (await service
        .exchange(baseSubject)
        .catch((e: OAuthError) => e)) as OAuthError;
      const unknownErr = (await (async () => {
        vi.mocked(idpPrisma.agentDefinition.findUnique).mockResolvedValue(
          null as never,
        );
        return service.exchange(baseSubject).catch((e: OAuthError) => e);
      })()) as OAuthError;

      expect(err.message).toBe(unknownErr.message);
      expect(err.code).toBe(unknownErr.code);
    });

    it("refuses a disabled agent", async () => {
      vi.mocked(idpPrisma.agentDefinition.findUnique).mockResolvedValue(
        agent({ status: "DISABLED" }) as never,
      );

      await expect(service.exchange(baseSubject)).rejects.toThrow(/not active/);
    });

    it("chains the delegation to the user's own session id", async () => {
      vi.mocked(idpPrisma.agentDefinition.findUnique).mockResolvedValue(
        agent() as never,
      );

      const grant = await service.exchange(baseSubject);

      expect(grant.sid).toBe("sess-1");
    });

    it("mints a short-lived grant, not the user's own session lifetime", async () => {
      vi.mocked(idpPrisma.agentDefinition.findUnique).mockResolvedValue(
        agent() as never,
      );

      const before = Date.now();
      const grant = await service.exchange(baseSubject);
      const ttlMs = grant.expiresAt.getTime() - before;

      expect(ttlMs).toBeGreaterThan(0);
      expect(ttlMs).toBeLessThanOrEqual(5 * 60_000 + 1000);
    });

    it("records the exchange with the effective permissions actually granted", async () => {
      vi.mocked(idpPrisma.agentDefinition.findUnique).mockResolvedValue(
        agent() as never,
      );

      await service.exchange(baseSubject);

      const written = vi.mocked(idpPrisma.agentDelegation.create).mock
        .calls[0][0] as {
        data: {
          tenantId: string;
          agentId: string;
          delegatingUserId: string;
          effectivePermissions: string[];
          sid: string;
        };
      };
      expect(written.data).toMatchObject({
        tenantId: "t1",
        agentId: "agent-1",
        delegatingUserId: "u1",
        sid: "sess-1",
      });
      expect(written.data.effectivePermissions.sort()).toEqual(
        ["finance.invoice.create", "finance.invoice.read"].sort(),
      );
    });
  });

  describe("currentEffectivePermissions", () => {
    it("recomputes against the live agent and live user permissions", async () => {
      vi.mocked(idpPrisma.agentDefinition.findUnique).mockResolvedValue(
        agent() as never,
      );

      const perms = await service.currentEffectivePermissions({
        agentId: "agent-1",
        tenantId: "t1",
        delegatingUserId: "u1",
        currentUserPermissions: ["finance.invoice.read"], // user demoted since exchange
      });

      expect(perms).toEqual(["finance.invoice.read"]);
    });

    it("returns nothing once the agent has been disabled", async () => {
      vi.mocked(idpPrisma.agentDefinition.findUnique).mockResolvedValue(
        agent({ status: "DISABLED" }) as never,
      );

      const perms = await service.currentEffectivePermissions({
        agentId: "agent-1",
        tenantId: "t1",
        delegatingUserId: "u1",
        currentUserPermissions: ["finance.invoice.read", "finance.invoice.create"],
      });

      expect(perms).toEqual([]);
    });

    it("returns nothing for an agent that no longer exists", async () => {
      vi.mocked(idpPrisma.agentDefinition.findUnique).mockResolvedValue(
        null as never,
      );

      const perms = await service.currentEffectivePermissions({
        agentId: "gone",
        tenantId: "t1",
        delegatingUserId: "u1",
        currentUserPermissions: ["finance.invoice.read"],
      });

      expect(perms).toEqual([]);
    });
  });
});
