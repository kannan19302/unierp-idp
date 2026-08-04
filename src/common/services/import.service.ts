import { Injectable, BadRequestException } from "@nestjs/common";
import { EventEmitter2 } from "@nestjs/event-emitter";
import { idpPrisma, prisma } from "@unerp/database";

interface ImportOptions {
  skipDuplicates?: boolean;
  updateExisting?: boolean;
  mapping?: Record<string, string>;
  batchSize?: number;
}

interface ImportResult {
  importId: string;
  total: number;
  succeeded: number;
  failed: number;
  errors: { row: number; message: string }[];
  status: "PROCESSING" | "COMPLETED" | "PARTIAL" | "FAILED";
}

interface ImportHistoryEntry {
  id: string;
  tenantId: string;
  userId: string;
  modelName: string;
  fileName: string;
  total: number;
  succeeded: number;
  failed: number;
  status: string;
  createdAt: Date;
}

interface ImportHistoryDetail extends ImportHistoryEntry {
  errors: { row: number; message: string }[];
  completedAt: Date | null;
}

const ALLOWED_IMPORT_MODELS = new Set([
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
  "account",
  "budget",
  "warehouse",
  "department",
  "designation",
  "project",
  "task",
  "opportunity",
  "campaign",
  "asset",
  "expenseClaim",
  "leaveApplication",
  "paymentEntry",
  "journalEntry",
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
  "account",
  "budget",
  "warehouse",
  "department",
  "designation",
  "project",
  "task",
  "opportunity",
  "campaign",
  "asset",
  "expenseClaim",
  "leaveApplication",
  "paymentEntry",
  "journalEntry",
]);

@Injectable()
export class ImportService {
  constructor(private readonly eventEmitter?: EventEmitter2) {}

  private validateModel(modelName: string): void {
    if (!ALLOWED_IMPORT_MODELS.has(modelName)) {
      throw new BadRequestException(
        `Model '${modelName}' is not supported for import`,
      );
    }
    const model = (prisma as any)[modelName];
    if (!model || typeof model.create !== "function") {
      throw new BadRequestException(`Invalid Prisma model: ${modelName}`);
    }
  }

  private addTenantScope(tenantId: string, modelName: string, data: any): any {
    if (TENANT_MODELS.has(modelName)) {
      return { ...data, tenantId };
    }
    return data;
  }

  private applyMapping(
    records: any[],
    mapping?: Record<string, string>,
  ): any[] {
    if (!mapping) return records;
    return records.map((record) => {
      const mapped: Record<string, any> = {};
      for (const [key, value] of Object.entries(record)) {
        const targetKey = mapping[key] || key;
        mapped[targetKey] = value;
      }
      return mapped;
    });
  }

  async importCsv(
    tenantId: string,
    userId: string,
    modelName: string,
    fileBuffer: Buffer,
    options: ImportOptions = {},
  ): Promise<ImportResult> {
    this.validateModel(modelName);

    let rows: any[];
    try {
      const csvString = fileBuffer.toString("utf-8");
      rows = this.parseCsv(csvString);
    } catch (err: any) {
      throw new BadRequestException(`Failed to parse CSV: ${err.message}`);
    }

    return this.processImport(
      tenantId,
      userId,
      modelName,
      rows,
      options,
      "import.csv",
    );
  }

  async importXlsx(
    tenantId: string,
    userId: string,
    modelName: string,
    fileBuffer: Buffer,
    options: ImportOptions = {},
  ): Promise<ImportResult> {
    this.validateModel(modelName);

    let rows: any[];
    try {
      rows = await this.parseXlsx(fileBuffer);
    } catch (err: any) {
      throw new BadRequestException(`Failed to parse XLSX: ${err.message}`);
    }

    return this.processImport(
      tenantId,
      userId,
      modelName,
      rows,
      options,
      "import.xlsx",
    );
  }

  async importJson(
    tenantId: string,
    userId: string,
    modelName: string,
    data: any[],
    options: ImportOptions = {},
  ): Promise<ImportResult> {
    this.validateModel(modelName);
    if (!Array.isArray(data) || data.length === 0) {
      throw new BadRequestException("JSON data must be a non-empty array");
    }
    return this.processImport(
      tenantId,
      userId,
      modelName,
      data,
      options,
      "import.json",
    );
  }

  private async processImport(
    tenantId: string,
    userId: string,
    modelName: string,
    rawRows: any[],
    options: ImportOptions,
    fileName: string,
  ): Promise<ImportResult> {
    const rows = this.applyMapping(rawRows, options.mapping);
    const batchSize = options.batchSize || 100;
    const result: ImportResult = {
      importId: "",
      total: rows.length,
      succeeded: 0,
      failed: 0,
      errors: [],
      status: "PROCESSING",
    };

    const importLog = await prisma.auditLog.create({
      data: {
        tenantId,
        userId,
        action: "IMPORT_STARTED",
        entityType: modelName,
        entityId: "import",
        changes: { total: rows.length, fileName, modelName },
      },
    });
    result.importId = importLog.id;

    for (let i = 0; i < rows.length; i += batchSize) {
      const batch = rows.slice(i, i + batchSize);
      await idpPrisma.$transaction(async (tx) => {
        for (let j = 0; j < batch.length; j++) {
          const rowIndex = i + j;
          try {
            const record = this.addTenantScope(tenantId, modelName, batch[j]);
            const where: any = { tenantId };

            if (options.skipDuplicates || options.updateExisting) {
              const uniqueFields = this.extractUniqueFields(modelName, record);
              if (uniqueFields) {
                const existing = await (tx as any)[modelName].findFirst({
                  where: { ...where, ...uniqueFields },
                });
                if (existing) {
                  if (options.updateExisting) {
                    await (tx as any)[modelName].update({
                      where: { id: existing.id },
                      data: record,
                    });
                    result.succeeded++;
                  } else {
                    result.succeeded++;
                  }
                  continue;
                }
              }
            }

            await (tx as any)[modelName].create({ data: record });
            result.succeeded++;
          } catch (err: any) {
            result.failed++;
            result.errors.push({
              row: rowIndex + 1,
              message: err.message || "Unknown error",
            });
          }
        }
      });
    }

    result.status =
      result.failed === 0
        ? "COMPLETED"
        : result.succeeded > 0
          ? "PARTIAL"
          : "FAILED";

    await prisma.auditLog.update({
      where: { id: result.importId },
      data: {
        changes: {
          total: result.total,
          succeeded: result.succeeded,
          failed: result.failed,
          status: result.status,
          fileName,
          modelName,
          errors: result.errors.slice(0, 100),
        },
      },
    });

    if (this.eventEmitter) {
      this.eventEmitter.emit("bulk-ops.import.completed", {
        tenantId,
        userId,
        modelName,
        importId: result.importId,
        total: result.total,
        succeeded: result.succeeded,
        failed: result.failed,
        status: result.status,
      });
    }

    return result;
  }

  private parseCsv(csvString: string): any[] {
    const lines = csvString
      .split(/\r?\n/)
      .filter((line) => line.trim().length > 0);
    if (lines.length < 2) {
      throw new BadRequestException(
        "CSV must have a header row and at least one data row",
      );
    }

    const headers = this.parseCsvLine(lines[0]!);
    const rows: any[] = [];

    for (let i = 1; i < lines.length; i++) {
      const values = this.parseCsvLine(lines[i]!);
      if (values.length === 0) continue;
      const row: Record<string, any> = {};
      for (let j = 0; j < headers.length; j++) {
        row[headers[j]!] =
          j < values.length ? this.coerceValue(values[j]) : null;
      }
      rows.push(row);
    }

    return rows;
  }

  private parseCsvLine(line: string): string[] {
    const values: string[] = [];
    let current = "";
    let inQuotes = false;

    for (let i = 0; i < line.length; i++) {
      const char = line[i];
      if (char === '"') {
        if (inQuotes && i + 1 < line.length && line[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          inQuotes = !inQuotes;
        }
      } else if (char === "," && !inQuotes) {
        values.push(current.trim());
        current = "";
      } else {
        current += char;
      }
    }
    values.push(current.trim());

    return values;
  }

  private async parseXlsx(buffer: Buffer): Promise<any[]> {
    const XLSX = await import("xlsx");
    const workbook = XLSX.read(buffer, { type: "buffer" });
    const sheetName = workbook.SheetNames[0];
    if (!sheetName) {
      throw new BadRequestException("XLSX file has no sheets");
    }
    const sheet = workbook.Sheets[sheetName]!;
    const jsonData: any[][] = XLSX.utils.sheet_to_json(sheet, { header: 1 });
    if (jsonData.length < 2) {
      throw new BadRequestException(
        "XLSX must have a header row and at least one data row",
      );
    }

    const headers = (jsonData[0] as string[]).map((h) => String(h).trim());
    const rows: any[] = [];

    for (let i = 1; i < jsonData.length; i++) {
      const values = jsonData[i] as any[];
      if (!values || values.length === 0) continue;
      const row: Record<string, any> = {};
      for (let j = 0; j < headers.length; j++) {
        row[headers[j]!] =
          j < values.length ? this.coerceValue(values[j]) : null;
      }
      rows.push(row);
    }

    return rows;
  }

  private coerceValue(value: any): any {
    if (value == null || value === "") return null;
    if (typeof value === "string") {
      if (value === "true" || value === "TRUE") return true;
      if (value === "false" || value === "FALSE") return false;
      if (/^-?\d+\.?\d*$/.test(value) && !isNaN(Number(value))) {
        return value.includes(".") ? parseFloat(value) : parseInt(value, 10);
      }
    }
    return value;
  }

  private extractUniqueFields(
    modelName: string,
    record: any,
  ): Record<string, any> | null {
    const uniqueFieldMap: Record<string, string[]> = {
      customer: ["email"],
      vendor: ["email"],
      contact: ["email"],
      lead: ["email"],
      employee: ["employeeCode", "email"],
      product: ["sku"],
      account: ["accountNumber", "name"],
      user: ["email"],
    };
    const fields = uniqueFieldMap[modelName];
    if (!fields) return null;
    for (const field of fields) {
      if (record[field] != null) {
        return { [field]: record[field] };
      }
    }
    return null;
  }

  async getImportHistory(
    tenantId: string,
    page = 1,
    limit = 20,
  ): Promise<{ data: ImportHistoryEntry[]; meta: any }> {
    const where = { tenantId, action: { startsWith: "IMPORT" } };
    const [data, total] = await Promise.all([
      prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: "desc" },
        skip: (page - 1) * limit,
        take: limit,
        select: {
          id: true,
          tenantId: true,
          userId: true,
          entityType: true,
          changes: true,
          createdAt: true,
        },
      }),
      prisma.auditLog.count({ where }),
    ]);

    return {
      data: data.map((entry) => {
        const changes = (entry.changes as any) || {};
        return {
          id: entry.id,
          tenantId: entry.tenantId,
          userId: entry.userId,
          modelName: entry.entityType,
          fileName: changes.fileName || "Unknown",
          total: changes.total || 0,
          succeeded: changes.succeeded || 0,
          failed: changes.failed || 0,
          status: changes.status || "UNKNOWN",
          createdAt: entry.createdAt,
        };
      }),
      meta: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  async getImportDetail(
    tenantId: string,
    importId: string,
  ): Promise<ImportHistoryDetail | null> {
    const entry = await prisma.auditLog.findFirst({
      where: { id: importId, tenantId, action: { startsWith: "IMPORT" } },
    });

    if (!entry) return null;

    const changes = (entry.changes as any) || {};
    return {
      id: entry.id,
      tenantId: entry.tenantId,
      userId: entry.userId,
      modelName: entry.entityType,
      fileName: changes.fileName || "Unknown",
      total: changes.total || 0,
      succeeded: changes.succeeded || 0,
      failed: changes.failed || 0,
      status: changes.status || "UNKNOWN",
      errors: changes.errors || [],
      createdAt: entry.createdAt,
      completedAt: entry.createdAt,
    };
  }
}
