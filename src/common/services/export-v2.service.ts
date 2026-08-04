import { Injectable, BadRequestException } from "@nestjs/common";
import { EventEmitter2 } from "@nestjs/event-emitter";
import { Response } from "express";
import { idpPrisma, prisma } from "@unerp/database";
import ExcelJS from "exceljs";
import PDFDocument from "pdfkit";
import {
  buildPaginationValues,
  paginatedResult,
  PaginatedResult,
  PaginationParams,
} from "../../common/utils/pagination.util";

interface ExportTemplate {
  name: string;
  columns: { header: string; key: string; width?: number; format?: string }[];
  title?: string;
  headerBgColor?: string;
  headerFontColor?: string;
  pageOrientation?: "portrait" | "landscape";
  pageSize?: string;
}

interface ChartConfig {
  type: "bar" | "line" | "pie" | "donut";
  title?: string;
  labels: string[];
  datasets: { label: string; data: number[]; color?: string }[];
}

interface ScheduledExportConfig {
  modelName: string;
  format: "csv" | "xlsx" | "pdf";
  template?: string;
  cronExpression: string;
  recipients: string[];
  filters?: Record<string, any>;
}

@Injectable()
export class ExportV2Service {
  constructor(private readonly eventEmitter?: EventEmitter2) {}

  private readonly defaultTemplates: Record<string, ExportTemplate> = {
    default: {
      name: "Default",
      columns: [],
      title: "Export",
      headerBgColor: "FF4472C4",
      headerFontColor: "FFFFFFFF",
      pageOrientation: "landscape",
      pageSize: "A4",
    },
    compact: {
      name: "Compact",
      columns: [],
      title: "Export",
      headerBgColor: "FF2E4053",
      headerFontColor: "FFFFFFFF",
      pageOrientation: "portrait",
      pageSize: "A4",
    },
    detailed: {
      name: "Detailed",
      columns: [],
      title: "Export",
      headerBgColor: "FF1A5276",
      headerFontColor: "FFFFFFFF",
      pageOrientation: "landscape",
      pageSize: "A3",
    },
  };

  async exportWithTemplates(
    res: Response,
    modelName: string,
    fields: { header: string; key: string; width?: number }[],
    rows: Record<string, any>[],
    template?: string,
    format: "csv" | "xlsx" | "pdf" = "xlsx",
  ): Promise<void> {
    let templateConfig: ExportTemplate = this.defaultTemplates.default!;
    if (template && this.defaultTemplates[template]) {
      templateConfig = this.defaultTemplates[template]!;
    }

    const columns = fields.length > 0 ? fields : templateConfig.columns;

    if (format === "csv") {
      await this.writeCsv(res, columns, rows, `export-${modelName}`);
    } else if (format === "pdf") {
      await this.writePdf(
        res,
        columns,
        rows,
        `export-${modelName}`,
        templateConfig.title || `Export: ${modelName}`,
      );
    } else {
      await this.writeStyledXlsx(
        res,
        columns,
        rows,
        `export-${modelName}`,
        templateConfig,
      );
    }
  }

  async exportWithCharts(
    res: Response,
    data: Record<string, any>[],
    chartConfig: ChartConfig,
    format: "pdf" | "xlsx" = "pdf",
  ): Promise<void> {
    const columns = chartConfig.datasets.map((ds) => ({
      header: ds.label,
      key: ds.label,
      width: 20,
    }));
    const chartRows = chartConfig.labels.map((label, i) => {
      const row: Record<string, any> = { label };
      chartConfig.datasets.forEach((ds) => {
        row[ds.label] = ds.data[i];
      });
      return row;
    });

    if (format === "xlsx") {
      const workbook = new ExcelJS.Workbook();
      workbook.creator = "UniERP";
      workbook.created = new Date();

      const dataSheet = workbook.addWorksheet("Data");
      dataSheet.columns = [
        { header: "Label", key: "label", width: 20 },
        ...columns,
      ];
      const headerRow = dataSheet.getRow(1);
      headerRow.font = { bold: true, color: { argb: "FFFFFFFF" } };
      headerRow.fill = {
        type: "pattern",
        pattern: "solid",
        fgColor: { argb: "FF4472C4" },
      };
      for (const row of chartRows) dataSheet.addRow(row);

      const chartSheet = workbook.addWorksheet("Chart");

      res.setHeader(
        "Content-Type",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      );
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="chart-export.xlsx"`,
      );
      await workbook.xlsx.write(res);
      res.end();
    } else {
      const doc = new PDFDocument({
        margin: 40,
        size: "A4",
        layout: "landscape",
      });
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader(
        "Content-Disposition",
        'attachment; filename="chart-export.pdf"',
      );
      doc.pipe(res);

      if (chartConfig.title) {
        doc
          .fontSize(18)
          .font("Helvetica-Bold")
          .text(chartConfig.title, { align: "center" });
        doc.moveDown(1);
      }

      doc.fontSize(10).font("Helvetica");
      const chartWidth = doc.page.width - 120;
      const chartHeight = 200;
      const chartX = 60;
      const chartY = doc.y;

      if (chartConfig.type === "bar") {
        this.drawBarChart(
          doc,
          chartConfig,
          chartX,
          chartY,
          chartWidth,
          chartHeight,
        );
      } else if (chartConfig.type === "line") {
        this.drawLineChart(
          doc,
          chartConfig,
          chartX,
          chartY,
          chartWidth,
          chartHeight,
        );
      } else if (chartConfig.type === "pie" || chartConfig.type === "donut") {
        this.drawPieChart(
          doc,
          chartConfig,
          chartX,
          chartY,
          chartWidth,
          chartHeight,
        );
      }

      doc.y = chartY + chartHeight + 40;

      const tableCols = [
        { header: "Label", key: "label", width: 100 },
        ...chartConfig.datasets.map((ds) => ({
          header: ds.label,
          key: ds.label,
          width: 80,
        })),
      ];

      doc
        .fontSize(12)
        .font("Helvetica-Bold")
        .text("Data Table", { align: "center" });
      doc.moveDown(0.5);
      doc.fontSize(8).font("Helvetica");

      const colWidth = (doc.page.width - 80) / tableCols.length;
      let x = 40;
      doc.font("Helvetica-Bold");
      for (const col of tableCols) {
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

      for (const row of chartRows) {
        if (doc.y > doc.page.height - 60) doc.addPage();
        x = 40;
        const rowY = doc.y;
        for (const col of tableCols) {
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

  private drawBarChart(
    doc: typeof PDFDocument.prototype,
    config: ChartConfig,
    x: number,
    y: number,
    width: number,
    height: number,
  ): void {
    const colors = [
      "#4472C4",
      "#ED7D31",
      "#70AD47",
      "#FFC000",
      "#5B9BD5",
      "#264478",
    ];
    const numBars = config.labels.length;
    const numDatasets = config.datasets.length;
    const groupWidth = width / numBars;
    const barWidth = Math.min(groupWidth / numDatasets - 4, 20);

    let maxVal = 0;
    for (const ds of config.datasets) {
      for (const v of ds.data) {
        if (v > maxVal) maxVal = v;
      }
    }
    if (maxVal === 0) maxVal = 1;

    const chartAreaHeight = height - 30;

    doc.save();
    doc.fontSize(7).font("Helvetica");

    for (let i = 0; i < numBars; i++) {
      for (let j = 0; j < numDatasets; j++) {
        const ds = config.datasets[j];
        if (!ds) continue;
        const barX = x + i * groupWidth + j * (barWidth + 2) + 4;
        const val = ds.data[i] ?? 0;
        const barH = (val / maxVal) * chartAreaHeight;
        const barY = y + chartAreaHeight - barH;

        doc.rect(barX, barY, barWidth, barH);
        doc.fillColor(ds.color || colors[j % colors.length]);
        doc.fill();
      }

      const labelX = x + i * groupWidth + groupWidth / 2;
      doc.fillColor("#333333");
      doc.text(
        config.labels[i]!.substring(0, 8),
        labelX - 15,
        y + chartAreaHeight + 5,
        { width: 30, align: "center" },
      );
    }

    doc.restore();
  }

  private drawLineChart(
    doc: typeof PDFDocument.prototype,
    config: ChartConfig,
    x: number,
    y: number,
    width: number,
    height: number,
  ): void {
    const colors = ["#4472C4", "#ED7D31", "#70AD47", "#FFC000", "#5B9BD5"];
    const chartAreaHeight = height - 30;
    let maxVal = 0;
    for (const ds of config.datasets) {
      for (const v of ds.data) {
        if (v > maxVal) maxVal = v;
      }
    }
    if (maxVal === 0) maxVal = 1;

    const pointSpacing = width / Math.max(config.labels.length - 1, 1);

    doc.save();
    doc.fontSize(7).font("Helvetica");

    for (let j = 0; j < config.datasets.length; j++) {
      const dsLine = config.datasets[j];
      if (!dsLine) continue;
      const color = dsLine.color || colors[j % colors.length];
      const firstVal = dsLine.data[0] ?? 0;

      doc.moveTo(
        x,
        y + chartAreaHeight - (firstVal / maxVal) * chartAreaHeight,
      );

      for (let i = 0; i < dsLine.data.length; i++) {
        const px = x + i * pointSpacing;
        const val = dsLine.data[i] ?? 0;
        const py = y + chartAreaHeight - (val / maxVal) * chartAreaHeight;
        doc.lineTo(px, py);
      }

      doc.strokeColor(color).lineWidth(1.5).stroke();

      for (let i = 0; i < dsLine.data.length; i++) {
        const px = x + i * pointSpacing;
        const val = dsLine.data[i] ?? 0;
        const py = y + chartAreaHeight - (val / maxVal) * chartAreaHeight;
        doc.circle(px, py, 2.5).fillColor(color).fill();
      }
    }

    doc.fillColor("#333333");
    for (let i = 0; i < config.labels.length; i++) {
      const labelX = x + i * pointSpacing;
      doc.text(
        config.labels[i]!.substring(0, 6),
        labelX - 12,
        y + chartAreaHeight + 5,
        { width: 24, align: "center" },
      );
    }

    doc.restore();
  }

  private drawPieChart(
    doc: typeof PDFDocument.prototype,
    config: ChartConfig,
    x: number,
    y: number,
    width: number,
    height: number,
  ): void {
    const colors = [
      "#4472C4",
      "#ED7D31",
      "#70AD47",
      "#FFC000",
      "#5B9BD5",
      "#264478",
      "#A5A5A5",
    ];
    const firstDs = config.datasets[0];
    if (!firstDs) return;
    const ds: { label: string; data: number[]; color?: string } = firstDs;

    const total = ds.data.reduce((sum: number, v: number) => sum + v, 0);
    if (total === 0) return;

    const cx = x + width / 2;
    const cy = y + height / 2;
    const radius = Math.min(width, height) / 2 - 20;
    const isDonut = config.type === "donut";

    let startAngle = -Math.PI / 2;

    doc.save();

    for (let i = 0; i < ds.data.length; i++) {
      const sliceAngle = ((ds.data[i] ?? 0) / total) * 2 * Math.PI;
      const endAngle = startAngle + sliceAngle;
      const color = colors[i % colors.length];

      const x1 = cx + radius * Math.cos(startAngle);
      const y1 = cy + radius * Math.sin(startAngle);
      const x2 = cx + radius * Math.cos(endAngle);
      const y2 = cy + radius * Math.sin(endAngle);

      const largeArc = sliceAngle > Math.PI ? 1 : 0;

      doc
        .moveTo(cx, cy)
        .lineTo(x1, y1)
        .arc(cx, cy, radius, startAngle, endAngle, false)
        .lineTo(cx, cy)
        .closePath()
        .fillColor(color)
        .fill();

      if (isDonut) {
        doc
          .circle(cx, cy, radius * 0.5)
          .fillColor("#FFFFFF")
          .fill();
      }

      startAngle = endAngle;
    }

    doc.restore();

    doc.fontSize(7).font("Helvetica");
    let legendY = y + height + 10;
    for (let i = 0; i < ds.data.length; i++) {
      const pct = (((ds.data[i] ?? 0) / total) * 100).toFixed(1);
      doc
        .rect(x, legendY, 8, 8)
        .fillColor(colors[i % colors.length])
        .fill();
      doc.fillColor("#333333");
      doc.text(`${config.labels[i]} (${pct}%)`, x + 12, legendY, {
        width: 200,
      });
      legendY += 12;
    }
  }

  async scheduleExport(
    tenantId: string,
    userId: string,
    config: ScheduledExportConfig,
  ): Promise<any> {
    const scheduledExport = await prisma.auditLog.create({
      data: {
        tenantId,
        userId,
        action: "EXPORT_SCHEDULED",
        entityType: "scheduled-export",
        entityId: "schedule",
        changes: {
          modelName: config.modelName,
          format: config.format,
          template: config.template,
          cronExpression: config.cronExpression,
          recipients: config.recipients,
          filters: config.filters,
        },
      },
    });

    if (this.eventEmitter) {
      this.eventEmitter.emit("export.scheduled", {
        tenantId,
        userId,
        exportId: scheduledExport.id,
        config,
      });
    }

    return {
      id: scheduledExport.id,
      ...config,
      createdAt: scheduledExport.createdAt,
    };
  }

  async getExportHistory(
    tenantId: string,
    pagination: PaginationParams,
  ): Promise<PaginatedResult<any>> {
    const { skip, take } = buildPaginationValues(pagination);
    const where = {
      tenantId,
      OR: [
        { action: { startsWith: "EXPORT" } },
        { action: "EXPORT_SCHEDULED" },
      ],
    };

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
        action: entry.action,
        details: entry.changes,
        createdAt: entry.createdAt,
      })),
      total,
      pagination,
    );
  }

  async bulkExport(
    tenantId: string,
    modelName: string,
    ids: string[],
    format: "csv" | "xlsx" | "pdf" = "csv",
    res?: Response,
  ): Promise<void> {
    const model = (prisma as any)[modelName];
    if (!model || typeof model.findMany !== "function") {
      throw new BadRequestException(`Invalid model: ${modelName}`);
    }

    const records = await model.findMany({
      where: { id: { in: ids }, tenantId, deletedAt: null },
    });

    if (records.length === 0) {
      throw new BadRequestException("No records found for the given IDs");
    }

    const fields = Object.keys(records[0])
      .filter(
        (k) => !["id", "tenantId", "deletedAt", "passwordHash"].includes(k),
      )
      .map((k) => ({
        header: k
          .replace(/([A-Z])/g, " $1")
          .replace(/^./, (s) => s.toUpperCase())
          .trim(),
        key: k,
        width: 20,
      }));

    await this.exportWithTemplates(
      res!,
      modelName,
      fields,
      records,
      "default",
      format,
    );

    if (this.eventEmitter) {
      this.eventEmitter.emit("export.bulk.completed", {
        tenantId,
        modelName,
        recordCount: records.length,
        format,
      });
    }
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
    res.write("\ufeff" + header + "\n");
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

  private async writeStyledXlsx(
    res: Response,
    columns: { header: string; key: string; width?: number }[],
    rows: Record<string, any>[],
    filename: string,
    template: ExportTemplate,
  ): Promise<void> {
    const workbook = new ExcelJS.Workbook();
    workbook.creator = "UniERP";
    workbook.created = new Date();
    const sheet = workbook.addWorksheet(template.name || "Export");

    sheet.columns = columns.map((c) => ({
      header: c.header,
      key: c.key,
      width: c.width || 20,
    }));

    const headerRow = sheet.getRow(1);
    headerRow.font = {
      bold: true,
      color: { argb: template.headerFontColor || "FFFFFFFF" },
    };
    headerRow.fill = {
      type: "pattern",
      pattern: "solid",
      fgColor: { argb: template.headerBgColor || "FF4472C4" },
    };

    for (const row of rows) {
      sheet.addRow(row);
    }

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
    doc.font("Helvetica-Bold");
    let x = 40;
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
