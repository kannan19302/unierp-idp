import { Injectable, BadRequestException } from "@nestjs/common";
import { EventEmitter2 } from "@nestjs/event-emitter";
import { Response } from "express";
import { idpPrisma, prisma } from "@unerp/database";
import {
  buildPaginationValues,
  paginatedResult,
  PaginatedResult,
  PaginationParams,
} from "../../common/utils/pagination.util";
import ExcelJS from "exceljs";
import PDFDocument from "pdfkit";

interface AuditLogEntry {
  id: string;
  tenantId: string;
  userId: string;
  action: string;
  entityType: string;
  entityId: string;
  changes: any;
  ipAddress?: string;
  userAgent?: string;
  createdAt: Date;
}

interface SecurityAuditEvent {
  id: string;
  userId: string;
  action: string;
  details: any;
  ipAddress?: string;
  createdAt: Date;
}

interface ComplianceReport {
  period: { startDate: Date; endDate: Date };
  totalEvents: number;
  byAction: Record<string, number>;
  byEntityType: Record<string, number>;
  topUsers: { userId: string; count: number }[];
  securityEvents: number;
  dataModifications: number;
  reportGeneratedAt: Date;
}

@Injectable()
export class EnterpriseAuditService {
  constructor(private readonly eventEmitter?: EventEmitter2) {}

  async logEvent(
    tenantId: string,
    userId: string,
    action: string,
    entityType: string,
    entityId: string,
    details?: Record<string, any>,
  ): Promise<void> {
    await prisma.auditLog.create({
      data: {
        tenantId,
        userId,
        action,
        entityType,
        entityId,
        changes: details || {},
        ipAddress: details?.ipAddress || null,
        userAgent: details?.userAgent || null,
      },
    });

    if (this.eventEmitter) {
      this.eventEmitter.emit("audit.logged", {
        tenantId,
        userId,
        action,
        entityType,
        entityId,
      });
    }
  }

  async getAuditTrail(
    tenantId: string,
    entityType: string,
    entityId: string,
    pagination: PaginationParams,
  ): Promise<PaginatedResult<AuditLogEntry>> {
    const { skip, take } = buildPaginationValues(pagination);
    const where = { tenantId, entityType, entityId };

    const [data, total] = await Promise.all([
      prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: "desc" },
        skip,
        take,
      }),
      prisma.auditLog.count({ where }),
    ]);

    return paginatedResult(data as any, total, pagination);
  }

  async getUserActivity(
    tenantId: string,
    userId: string,
    dateRange?: { startDate?: Date; endDate?: Date },
    pagination: PaginationParams = {},
  ): Promise<PaginatedResult<AuditLogEntry>> {
    const { skip, take } = buildPaginationValues(pagination);
    const where: any = { tenantId, userId };

    if (dateRange?.startDate || dateRange?.endDate) {
      where.createdAt = {};
      if (dateRange.startDate) where.createdAt.gte = dateRange.startDate;
      if (dateRange.endDate) where.createdAt.lte = dateRange.endDate;
    }

    const [data, total] = await Promise.all([
      prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: "desc" },
        skip,
        take,
      }),
      prisma.auditLog.count({ where }),
    ]);

    return paginatedResult(data as any, total, pagination);
  }

  async getSecurityAudit(
    tenantId: string,
    dateRange?: { startDate?: Date; endDate?: Date },
    pagination: PaginationParams = {},
  ): Promise<PaginatedResult<SecurityAuditEvent>> {
    const { skip, take } = buildPaginationValues(pagination);
    const securityActions = [
      "LOGIN",
      "LOGIN_FAILED",
      "LOGOUT",
      "PASSWORD_CHANGE",
      "PASSWORD_RESET",
      "PERMISSION_CHANGE",
      "ROLE_CHANGE",
      "MFA_ENABLED",
      "MFA_DISABLED",
      "API_KEY_CREATED",
      "API_KEY_REVOKED",
      "ACCOUNT_LOCKED",
      "ACCOUNT_UNLOCKED",
      "TWO_FACTOR_ENABLED",
      "TWO_FACTOR_DISABLED",
      "SESSION_REVOKED",
      "SECURITY_SETTING_CHANGED",
      "LOGIN_FROM_NEW_DEVICE",
    ];

    const where: any = {
      tenantId,
      action: { in: securityActions },
    };

    if (dateRange?.startDate || dateRange?.endDate) {
      where.createdAt = {};
      if (dateRange.startDate) where.createdAt.gte = dateRange.startDate;
      if (dateRange.endDate) where.createdAt.lte = dateRange.endDate;
    }

    const [data, total] = await Promise.all([
      prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: "desc" },
        skip,
        take,
      }),
      prisma.auditLog.count({ where }),
    ]);

    return paginatedResult(
      data.map((entry) => ({
        id: entry.id,
        userId: entry.userId,
        action: entry.action,
        details: entry.changes,
        ipAddress: entry.ipAddress || undefined,
        createdAt: entry.createdAt,
      })) as any,
      total,
      pagination,
    );
  }

  async exportAuditLog(
    tenantId: string,
    format: "csv" | "xlsx" | "pdf",
    dateRange?: { startDate?: Date; endDate?: Date },
    res?: Response,
  ): Promise<void> {
    const where: any = { tenantId };
    if (dateRange?.startDate || dateRange?.endDate) {
      where.createdAt = {};
      if (dateRange.startDate) where.createdAt.gte = dateRange.startDate;
      if (dateRange.endDate) where.createdAt.lte = dateRange.endDate;
    }

    const data = await prisma.auditLog.findMany({
      where,
      orderBy: { createdAt: "desc" },
      take: 10000,
    });

    const columns = [
      { header: "Date", key: "createdAt", width: 25 },
      { header: "User ID", key: "userId", width: 30 },
      { header: "Action", key: "action", width: 20 },
      { header: "Entity Type", key: "entityType", width: 20 },
      { header: "Entity ID", key: "entityId", width: 30 },
      { header: "IP Address", key: "ipAddress", width: 20 },
    ];

    const rows = data.map((entry) => ({
      createdAt: entry.createdAt.toISOString(),
      userId: entry.userId,
      action: entry.action,
      entityType: entry.entityType,
      entityId: entry.entityId,
      ipAddress: entry.ipAddress || "",
    }));

    if (format === "csv") {
      await this.writeCsv(res!, columns, rows, "audit-log");
    } else if (format === "xlsx") {
      await this.writeXlsx(res!, columns, rows, "audit-log");
    } else if (format === "pdf") {
      await this.writePdf(res!, columns, rows, "audit-log", "Audit Log Export");
    }
  }

  async getComplianceReport(
    tenantId: string,
    startDate: Date,
    endDate: Date,
  ): Promise<ComplianceReport> {
    const where = {
      tenantId,
      createdAt: { gte: startDate, lte: endDate },
    };

    const allEvents = await prisma.auditLog.findMany({ where });

    const byAction: Record<string, number> = {};
    const byEntityType: Record<string, number> = {};
    const userCounts: Record<string, number> = {};

    let securityEvents = 0;
    const securityActions = new Set([
      "LOGIN",
      "LOGIN_FAILED",
      "LOGOUT",
      "PASSWORD_CHANGE",
      "PASSWORD_RESET",
      "PERMISSION_CHANGE",
      "ROLE_CHANGE",
      "MFA_ENABLED",
      "MFA_DISABLED",
      "API_KEY_CREATED",
      "API_KEY_REVOKED",
      "ACCOUNT_LOCKED",
      "ACCOUNT_UNLOCKED",
      "SESSION_REVOKED",
    ]);

    for (const event of allEvents) {
      byAction[event.action] = (byAction[event.action] || 0) + 1;
      byEntityType[event.entityType] =
        (byEntityType[event.entityType] || 0) + 1;
      userCounts[event.userId] = (userCounts[event.userId] || 0) + 1;
      if (securityActions.has(event.action)) securityEvents++;
    }

    const topUsers = Object.entries(userCounts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10)
      .map(([userId, count]) => ({ userId, count }));

    const dataModifications = allEvents.filter((e) =>
      ["CREATE", "UPDATE", "DELETE"].includes(e.action),
    ).length;

    return {
      period: { startDate, endDate },
      totalEvents: allEvents.length,
      byAction,
      byEntityType,
      topUsers,
      securityEvents,
      dataModifications,
      reportGeneratedAt: new Date(),
    };
  }

  private async writeCsv(
    res: Response,
    columns: { header: string; key: string }[],
    rows: Record<string, any>[],
    filename: string,
  ): Promise<void> {
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${filename}.csv"`,
    );
    const header = columns.map((c) => `"${c.header}"`).join(",");
    res.write(header + "\n");
    for (const row of rows) {
      const line = columns
        .map((c) => {
          const val = row[c.key];
          return `"${val != null ? String(val).replace(/"/g, '""') : ""}"`;
        })
        .join(",");
      res.write(line + "\n");
    }
    res.end();
  }

  private async writeXlsx(
    res: Response,
    columns: { header: string; key: string; width?: number }[],
    rows: Record<string, any>[],
    filename: string,
  ): Promise<void> {
    const workbook = new ExcelJS.Workbook();
    workbook.creator = "UniERP";
    workbook.created = new Date();
    const sheet = workbook.addWorksheet("Audit Log");
    sheet.columns = columns.map((c) => ({
      header: c.header,
      key: c.key,
      width: c.width || 20,
    }));
    const headerRow = sheet.getRow(1);
    headerRow.font = { bold: true, color: { argb: "FFFFFFFF" } };
    headerRow.fill = {
      type: "pattern",
      pattern: "solid",
      fgColor: { argb: "FF4472C4" },
    };
    for (const row of rows) sheet.addRow(row);
    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    );
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${filename}.xlsx"`,
    );
    await workbook.xlsx.write(res);
    res.end();
  }

  private async writePdf(
    res: Response,
    columns: { header: string; key: string }[],
    rows: Record<string, any>[],
    filename: string,
    title: string,
  ): Promise<void> {
    const doc = new PDFDocument({
      margin: 40,
      size: "A4",
      layout: "landscape",
    });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${filename}.pdf"`,
    );
    doc.pipe(res);
    if (title) {
      doc.fontSize(16).font("Helvetica-Bold").text(title, { align: "center" });
      doc.moveDown(0.5);
    }
    doc.fontSize(8).font("Helvetica");
    const colWidth = (doc.page.width - 80) / columns.length;
    let x = 40;
    doc.font("Helvetica-Bold");
    for (const col of columns) {
      doc.text(col.header, x, doc.y, { width: colWidth, continued: false });
      x += colWidth;
    }
    doc.moveDown(0.3);
    doc
      .moveTo(40, doc.y)
      .lineTo(doc.page.width - 40, doc.y)
      .stroke();
    doc.moveDown(0.3);
    doc.font("Helvetica");
    for (const row of rows) {
      if (doc.y > doc.page.height - 60) doc.addPage();
      x = 40;
      const rowY = doc.y;
      for (const col of columns) {
        doc.text(row[col.key] != null ? String(row[col.key]) : "", x, rowY, {
          width: colWidth,
          continued: false,
        });
        x += colWidth;
      }
      doc.moveDown(0.2);
    }
    doc
      .fontSize(7)
      .text(
        `Generated by UniERP on ${new Date().toISOString().slice(0, 10)}`,
        40,
        doc.page.height - 30,
        { align: "center" },
      );
    doc.end();
  }
}
