/**
 * Reads a Role.permissions value.
 *
 * The column is Prisma `Json`, and the codebase writes it two different ways:
 *
 *   * the application double-encodes — `permissions: JSON.stringify(["*"])`
 *     (auth.service.ts:356, :1598) — so the column holds a JSON *string*;
 *   * the canonical seed writes a plain array — `permissions: ["*"]`
 *     (data/prisma/seed.ts) — so the column holds a JSON *array*.
 *
 * Every reader assumed the first shape: `JSON.parse(row.permissions as string)`.
 * Given an array, Prisma returns an array, `JSON.parse` coerces it to
 * "finance.invoice.read,saas.read", that is not valid JSON, and the throw was
 * swallowed by a bare `catch {}`. The role resolved to **zero permissions** and
 * nothing anywhere reported a problem — a seeded environment simply behaved as
 * though every user were unprivileged, which reads as a data problem rather
 * than a parsing one.
 *
 * Accepting both shapes is the fix that cannot regress: it does not require
 * every writer in two repositories to agree first, and normalising the column
 * later does not break this reader.
 */
// Kept as a compatibility import path for Identity call sites while the
// implementation lives in shared and is consumed by API/PCC/OCC as well.
export { parseRolePermissions } from "@kannan19302/shared";
