export interface PaginatedResult<T> {
  data: T[];
  meta: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

export interface PaginationParams {
  page?: number;
  limit?: number;
  sort?: string;
  search?: string;
}

/**
 * Build pagination skip/take values.
 */
export function buildPaginationValues(params: PaginationParams): {
  skip: number;
  take: number;
} {
  // page/limit arrive as raw query-string values at some call sites (e.g.
  // controllers that pass `@Query() q: any` straight through), so they can
  // be strings here even though PaginationParams types them as numbers —
  // coerce defensively or Prisma's `take`/`skip` throw ("Expected Int,
  // provided String").
  const page = Number(params.page) || 1;
  const limit = Number(params.limit) || 25;
  const skip = (page - 1) * limit;
  return { skip, take: limit };
}

/**
 * Build Prisma orderBy from sort param string.
 * Handles multi-field sorting (e.g., "name,-createdAt").
 * Returns a generic array that can be cast to the specific model's type.
 */
export function buildOrderBy(sort?: string): Record<string, "asc" | "desc">[] {
  if (!sort) return [{ createdAt: "desc" }];
  const fields = sort.split(",");
  return fields.map((field) => {
    const desc = field.startsWith("-");
    const key = desc ? field.substring(1) : field;
    return { [key]: desc ? "desc" : "asc" };
  });
}

/**
 * Wrap data with pagination meta.
 */
export function paginatedResult<T>(
  data: T[],
  total: number,
  params: PaginationParams,
): PaginatedResult<T> {
  const page = params.page || 1;
  const limit = params.limit || 25;
  return {
    data,
    meta: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    },
  };
}

/**
 * Resolve organization ID, using the first org for the tenant if not provided.
 */
export async function resolveOrgId(
  tenantId: string,
  orgId?: string,
): Promise<string> {
  if (orgId && orgId !== "org-system-default") return orgId;
  const { prisma } = await import("@unerp/database");
  const org = await prisma.organization.findFirst({
    where: { tenantId },
    select: { id: true },
  });
  if (!org) {
    const { BadRequestException } = await import("@nestjs/common");
    throw new BadRequestException(
      "No Organization found. Register an Organization first.",
    );
  }
  return org.id;
}
