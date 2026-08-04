import {
  Injectable,
  BadRequestException,
  NotFoundException,
} from "@nestjs/common";
import { EventEmitter2 } from "@nestjs/event-emitter";
import { idpPrisma, prisma } from "@unerp/database";

interface BulkOperationResult {
  succeeded: number;
  failed: number;
  errors: { index?: number; id?: string; message: string }[];
  total: number;
}

const ALLOWED_BULK_MODELS = new Set([
  "customer",
  "vendor",
  "contact",
  "lead",
  "employee",
  "product",
  "invoice",
  "purchaseOrder",
  "salesOrder",
  "quotation",
  "deliveryNote",
  "paymentEntry",
  "journalEntry",
  "project",
  "task",
  "warehouse",
  "user",
  "role",
  "account",
  "budget",
  "asset",
  "department",
  "designation",
  "leaveApplication",
  "expenseClaim",
  "opportunity",
  "campaign",
]);

const TENANT_MODELS = new Set([
  "customer",
  "vendor",
  "contact",
  "lead",
  "employee",
  "product",
  "invoice",
  "purchaseOrder",
  "salesOrder",
  "quotation",
  "deliveryNote",
  "paymentEntry",
  "journalEntry",
  "project",
  "task",
  "warehouse",
  "account",
  "budget",
  "asset",
  "department",
  "designation",
  "leaveApplication",
  "expenseClaim",
  "opportunity",
  "campaign",
]);

@Injectable()
export class BulkOperationsService {
  constructor(private readonly eventEmitter?: EventEmitter2) {}

  private getModel(modelName: string): any {
    if (!ALLOWED_BULK_MODELS.has(modelName)) {
      throw new BadRequestException(
        `Model '${modelName}' is not allowed for bulk operations`,
      );
    }
    const model = (prisma as any)[modelName];
    if (!model || typeof model.create !== "function") {
      throw new BadRequestException(`Invalid Prisma model: ${modelName}`);
    }
    return model;
  }

  private addTenantScope(tenantId: string, modelName: string, data: any): any {
    if (TENANT_MODELS.has(modelName)) {
      return { ...data, tenantId };
    }
    return data;
  }

  async bulkCreate(
    tenantId: string,
    modelName: string,
    records: any[],
  ): Promise<BulkOperationResult> {
    if (!records || records.length === 0) {
      throw new BadRequestException("Records array is required");
    }
    const model = this.getModel(modelName);
    const result: BulkOperationResult = {
      succeeded: 0,
      failed: 0,
      errors: [],
      total: records.length,
    };

    await idpPrisma.$transaction(async (tx) => {
      for (let i = 0; i < records.length; i++) {
        try {
          const record = this.addTenantScope(tenantId, modelName, records[i]);
          await (tx as any)[modelName].create({ data: record });
          result.succeeded++;
        } catch (err: any) {
          result.failed++;
          result.errors.push({
            index: i,
            message: err.message || "Unknown error",
          });
        }
      }
    });

    if (this.eventEmitter) {
      this.eventEmitter.emit("bulk-ops.create.completed", {
        tenantId,
        modelName,
        succeeded: result.succeeded,
        failed: result.failed,
        total: result.total,
      });
    }

    return result;
  }

  async bulkUpdate(
    tenantId: string,
    modelName: string,
    ids: string[],
    updates: Record<string, any>,
  ): Promise<BulkOperationResult> {
    if (!ids || ids.length === 0) {
      throw new BadRequestException("IDs array is required");
    }
    const model = this.getModel(modelName);
    const result: BulkOperationResult = {
      succeeded: 0,
      failed: 0,
      errors: [],
      total: ids.length,
    };

    await idpPrisma.$transaction(async (tx) => {
      for (const id of ids) {
        try {
          const where: any = { id };
          if (TENANT_MODELS.has(modelName)) {
            where.tenantId = tenantId;
          }
          const existing = await (tx as any)[modelName].findUnique({ where });
          if (!existing) {
            result.failed++;
            result.errors.push({ id, message: `Record ${id} not found` });
            continue;
          }
          await (tx as any)[modelName].update({ where, data: updates });
          result.succeeded++;
        } catch (err: any) {
          result.failed++;
          result.errors.push({ id, message: err.message || "Unknown error" });
        }
      }
    });

    if (this.eventEmitter) {
      this.eventEmitter.emit("bulk-ops.update.completed", {
        tenantId,
        modelName,
        succeeded: result.succeeded,
        failed: result.failed,
        total: result.total,
      });
    }

    return result;
  }

  async bulkDelete(
    tenantId: string,
    modelName: string,
    ids: string[],
  ): Promise<BulkOperationResult> {
    if (!ids || ids.length === 0) {
      throw new BadRequestException("IDs array is required");
    }
    const model = this.getModel(modelName);
    const result: BulkOperationResult = {
      succeeded: 0,
      failed: 0,
      errors: [],
      total: ids.length,
    };

    await idpPrisma.$transaction(async (tx) => {
      for (const id of ids) {
        try {
          const where: any = { id };
          if (TENANT_MODELS.has(modelName)) {
            where.tenantId = tenantId;
          }
          const existing = await (tx as any)[modelName].findUnique({ where });
          if (!existing) {
            result.failed++;
            result.errors.push({ id, message: `Record ${id} not found` });
            continue;
          }
          const updateData: any = { deletedAt: new Date() };
          if (TENANT_MODELS.has(modelName)) {
            await (tx as any)[modelName].update({ where, data: updateData });
          } else {
            await (tx as any)[modelName].update({ where, data: updateData });
          }
          result.succeeded++;
        } catch (err: any) {
          result.failed++;
          result.errors.push({ id, message: err.message || "Unknown error" });
        }
      }
    });

    if (this.eventEmitter) {
      this.eventEmitter.emit("bulk-ops.delete.completed", {
        tenantId,
        modelName,
        succeeded: result.succeeded,
        failed: result.failed,
        total: result.total,
      });
    }

    return result;
  }

  async bulkRestore(
    tenantId: string,
    modelName: string,
    ids: string[],
  ): Promise<BulkOperationResult> {
    if (!ids || ids.length === 0) {
      throw new BadRequestException("IDs array is required");
    }
    this.getModel(modelName);
    const result: BulkOperationResult = {
      succeeded: 0,
      failed: 0,
      errors: [],
      total: ids.length,
    };

    await idpPrisma.$transaction(async (tx) => {
      for (const id of ids) {
        try {
          const where: any = { id };
          if (TENANT_MODELS.has(modelName)) {
            where.tenantId = tenantId;
          }
          const existing = await (tx as any)[modelName].findUnique({ where });
          if (!existing) {
            result.failed++;
            result.errors.push({ id, message: `Record ${id} not found` });
            continue;
          }
          await (tx as any)[modelName].update({
            where,
            data: { deletedAt: null },
          });
          result.succeeded++;
        } catch (err: any) {
          result.failed++;
          result.errors.push({ id, message: err.message || "Unknown error" });
        }
      }
    });

    if (this.eventEmitter) {
      this.eventEmitter.emit("bulk-ops.restore.completed", {
        tenantId,
        modelName,
        succeeded: result.succeeded,
        failed: result.failed,
        total: result.total,
      });
    }

    return result;
  }

  async bulkStatusChange(
    tenantId: string,
    modelName: string,
    ids: string[],
    status: string,
  ): Promise<BulkOperationResult> {
    if (!ids || ids.length === 0) {
      throw new BadRequestException("IDs array is required");
    }
    if (!status) {
      throw new BadRequestException("Status value is required");
    }
    this.getModel(modelName);
    const result: BulkOperationResult = {
      succeeded: 0,
      failed: 0,
      errors: [],
      total: ids.length,
    };

    await idpPrisma.$transaction(async (tx) => {
      for (const id of ids) {
        try {
          const where: any = { id };
          if (TENANT_MODELS.has(modelName)) {
            where.tenantId = tenantId;
          }
          const existing = await (tx as any)[modelName].findUnique({ where });
          if (!existing) {
            result.failed++;
            result.errors.push({ id, message: `Record ${id} not found` });
            continue;
          }
          await (tx as any)[modelName].update({ where, data: { status } });
          result.succeeded++;
        } catch (err: any) {
          result.failed++;
          result.errors.push({ id, message: err.message || "Unknown error" });
        }
      }
    });

    if (this.eventEmitter) {
      this.eventEmitter.emit("bulk-ops.status-change.completed", {
        tenantId,
        modelName,
        status,
        succeeded: result.succeeded,
        failed: result.failed,
        total: result.total,
      });
    }

    return result;
  }
}
