/**
 * Maps Prisma model names to the app slug that owns them.
 *
 * Used by StorageMeteringService to compute per-app storage. Unmapped models
 * fall into the "platform" bucket (not attributed to any toggleable app).
 *
 * This registry is intentionally incomplete on day one — start with the primary
 * models for each installable app, then grow incrementally. There is no need
 * for 100% coverage of ~700 models to produce useful per-app storage numbers.
 */
export const APP_MODEL_OWNERSHIP: Record<string, string> = {
  // ── Finance ──
  Invoice: "finance",
  InvoiceLineItem: "finance",
  Payment: "finance",
  JournalEntry: "finance",
  JournalEntryLine: "finance",
  ChartOfAccount: "finance",
  TaxRate: "finance",
  TaxReturn: "finance",
  BankAccount: "finance",
  BankTransaction: "finance",
  Budget: "finance",
  BudgetAllocation: "finance",
  FinancialYear: "finance",

  // ── HR ──
  Employee: "hr",
  EmployeeDocument: "hr",
  Department: "hr",
  LeaveRequest: "hr",
  LeavePolicy: "hr",
  Attendance: "hr",
  AttendanceShift: "hr",
  PayrollRun: "hr",
  PayrollEntry: "hr",
  SalaryStructure: "hr",
  PerformanceReview: "hr",
  TrainingProgram: "hr",
  Certification: "hr",

  // ── CRM ──
  Customer: "crm",
  Contact: "crm",
  Lead: "crm",
  Opportunity: "crm",
  Account: "crm",

  // ── Inventory ──
  Product: "inventory",
  Warehouse: "inventory",
  StockMovement: "inventory",
  StockLevel: "inventory",
  BinLocation: "inventory",

  // ── Procurement ──
  Vendor: "procurement",
  PurchaseOrder: "procurement",
  PurchaseOrderItem: "procurement",
  RequestForQuotation: "procurement",
  GoodsReceiptNote: "procurement",

  // ── Sales ──
  SalesOrder: "sales",
  SalesOrderItem: "sales",
  Quotation: "sales",
  DeliveryNote: "sales",
  CreditNote: "sales",

  // ── Supply Chain ──
  Shipment: "supply-chain",
  Carrier: "supply-chain",
  DemandForecast: "supply-chain",

  // ── Projects ──
  Project: "projects",
  Task: "projects",
  Milestone: "projects",
  Timesheet: "projects",
  ProjectBudget: "projects",

  // ── Manufacturing ──
  BillOfMaterial: "manufacturing",
  BomItem: "manufacturing",
  WorkOrder: "manufacturing",
  WorkOrderOperation: "manufacturing",
  Workstation: "manufacturing",

  // ── Analytics ──
  ReportDefinition: "analytics",
  DashboardWidget: "analytics",
  ScheduledReport: "analytics",

  // ── Drive ──
  DriveDocument: "drive",
  DriveFolder: "drive",
  FileVersion: "drive",

  // ── Communication ──
  Message: "communication",
  Channel: "communication",
  CalendarEvent: "communication",

  // ── POS ──
  PosShift: "pos",
  PosRegister: "pos",
  PosTransaction: "pos",
};

/**
 * Returns the owning app slug for a Prisma model, or "platform" if unmapped.
 */
export function ownerForModel(modelName: string): string {
  return APP_MODEL_OWNERSHIP[modelName] || "platform";
}

/**
 * Set of model names that are explicitly tracked (for quick membership check).
 */
export const TRACKED_MODELS = new Set(Object.keys(APP_MODEL_OWNERSHIP));
