/**
 * Deprecation headers middleware (Foundation Roadmap Track G.1).
 *
 * Emits, for any request whose path matches the deprecation registry:
 *   Deprecation: @<unix-timestamp>          (RFC 9745)
 *   Sunset: <HTTP-date>                     (RFC 8594, when a date is set)
 *   Link: <successor>; rel="successor-version" / rel="deprecation"
 *
 * Registry empty ⇒ zero-cost no-op. Clients and the extension gateway can
 * rely on these headers programmatically (see docs/API_VERSIONING_POLICY.md).
 */
import type { NextFunction, Request, Response } from "express";
import {
  API_DEPRECATIONS,
  findDeprecation,
  type DeprecationEntry,
} from "./deprecation-registry";

export function applyDeprecationHeaders(
  response: Response,
  entry: DeprecationEntry,
): void {
  response.setHeader(
    "Deprecation",
    `@${Math.floor(entry.deprecatedAt.getTime() / 1000)}`,
  );
  if (entry.sunsetAt)
    response.setHeader("Sunset", entry.sunsetAt.toUTCString());
  const links: string[] = [];
  if (entry.successor)
    links.push(`<${entry.successor}>; rel="successor-version"`);
  if (entry.link) links.push(`<${entry.link}>; rel="deprecation"`);
  if (links.length > 0) response.setHeader("Link", links.join(", "));
}

export function deprecationMiddleware(
  registry: DeprecationEntry[] = API_DEPRECATIONS,
) {
  return (request: Request, response: Response, next: NextFunction): void => {
    const entry = findDeprecation(request.path, registry);
    if (entry) applyDeprecationHeaders(response, entry);
    next();
  };
}
