import { Injectable } from "@nestjs/common";
import { idpPrisma, prisma } from "@kannan19302/database";
import type { FieldChange, ChangeAction } from "@kannan19302/shared";

const SKIP_FIELDS = new Set([
  "updatedAt",
  "updated_at",
  "passwordHash",
  "password_hash",
  "deletedAt",
  "deleted_at",
  "tenantId",
  "tenant_id",
]);

@Injectable()
export class ChangeHistoryService {
  diffFields(
    oldData: Record<string, unknown>,
    newData: Record<string, unknown>,
  ): FieldChange[] {
    const changes: FieldChange[] = [];
    const allKeys = new Set([...Object.keys(oldData), ...Object.keys(newData)]);

    for (const key of allKeys) {
      if (SKIP_FIELDS.has(key)) continue;
      const oldVal = oldData[key];
      const newVal = newData[key];
      if (JSON.stringify(oldVal) !== JSON.stringify(newVal)) {
        changes.push({
          field: key,
          label: key
            .replace(/([A-Z])/g, " $1")
            .replace(/^./, (s) => s.toUpperCase())
            .trim(),
          oldValue: oldVal ?? null,
          newValue: newVal ?? null,
        });
      }
    }
    return changes;
  }

  async recordChange(params: {
    tenantId: string;
    userId: string;
    userName: string;
    entityType: string;
    entityId: string;
    action: ChangeAction;
    fieldChanges: FieldChange[];
    metadata?: Record<string, unknown>;
  }) {
    return prisma.changeHistory.create({
      data: {
        tenantId: params.tenantId,
        userId: params.userId,
        userName: params.userName,
        entityType: params.entityType,
        entityId: params.entityId,
        action: params.action,
        fieldChanges: JSON.stringify(params.fieldChanges),
        metadata: params.metadata ? JSON.stringify(params.metadata) : undefined,
      },
    });
  }

  async getHistory(
    tenantId: string,
    entityType: string,
    entityId: string,
    page = 1,
    limit = 20,
  ) {
    const where = { tenantId, entityType, entityId };
    const [data, total] = await Promise.all([
      prisma.changeHistory.findMany({
        where,
        orderBy: { createdAt: "desc" },
        skip: (page - 1) * limit,
        take: limit,
      }),
      prisma.changeHistory.count({ where }),
    ]);

    return {
      data: data.map((entry) => ({
        ...entry,
        fieldChanges:
          typeof entry.fieldChanges === "string"
            ? JSON.parse(entry.fieldChanges as string)
            : entry.fieldChanges,
        metadata:
          entry.metadata && typeof entry.metadata === "string"
            ? JSON.parse(entry.metadata as string)
            : entry.metadata,
      })),
      meta: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    };
  }
}
