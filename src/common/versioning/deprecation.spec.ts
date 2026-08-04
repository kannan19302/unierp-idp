import { describe, expect, it } from "vitest";
import { findDeprecation, type DeprecationEntry } from "./deprecation-registry";
import {
  applyDeprecationHeaders,
  deprecationMiddleware,
} from "./deprecation.middleware";

const registry: DeprecationEntry[] = [
  {
    pathPrefix: "/api/v1/legacy-reports",
    deprecatedAt: new Date("2026-07-01T00:00:00Z"),
    sunsetAt: new Date("2027-01-01T00:00:00Z"),
    successor: "/api/v2/reports",
    link: "https://docs.unerp.dev/migrations/reports-v2",
  },
  {
    pathPrefix: "/api/v1/legacy-reports/exports",
    deprecatedAt: new Date("2026-06-01T00:00:00Z"),
  },
];

function fakeResponse() {
  const headers: Record<string, string> = {};
  return {
    headers,
    setHeader: (name: string, value: string) => {
      headers[name] = value;
    },
  };
}

describe("deprecation registry (Track G.1)", () => {
  it("longest-prefix wins for nested surfaces", () => {
    expect(
      findDeprecation("/api/v1/legacy-reports/summary", registry)?.pathPrefix,
    ).toBe("/api/v1/legacy-reports");
    expect(
      findDeprecation("/api/v1/legacy-reports/exports/csv", registry)
        ?.pathPrefix,
    ).toBe("/api/v1/legacy-reports/exports");
  });

  it("returns null for unregistered paths (and the live registry is empty)", () => {
    expect(findDeprecation("/api/v1/orders", registry)).toBeNull();
    expect(findDeprecation("/api/v1/anything")).toBeNull();
  });
});

describe("deprecation headers (Track G.1)", () => {
  it("emits RFC 9745 Deprecation, RFC 8594 Sunset, and successor Links", () => {
    const response = fakeResponse();
    applyDeprecationHeaders(response as never, registry[0]);
    expect(response.headers["Deprecation"]).toBe(
      `@${Math.floor(registry[0].deprecatedAt.getTime() / 1000)}`,
    );
    expect(response.headers["Sunset"]).toBe("Fri, 01 Jan 2027 00:00:00 GMT");
    expect(response.headers["Link"]).toContain('rel="successor-version"');
    expect(response.headers["Link"]).toContain('rel="deprecation"');
  });

  it("omits Sunset/Link when not declared", () => {
    const response = fakeResponse();
    applyDeprecationHeaders(response as never, registry[1]);
    expect(response.headers["Deprecation"]).toBeDefined();
    expect(response.headers["Sunset"]).toBeUndefined();
    expect(response.headers["Link"]).toBeUndefined();
  });

  it("middleware decorates matching requests and ignores others", () => {
    const middleware = deprecationMiddleware(registry);
    const hit = fakeResponse();
    let nextCalls = 0;
    middleware(
      { path: "/api/v1/legacy-reports" } as never,
      hit as never,
      () => {
        nextCalls += 1;
      },
    );
    const miss = fakeResponse();
    middleware({ path: "/api/v1/orders" } as never, miss as never, () => {
      nextCalls += 1;
    });
    expect(nextCalls).toBe(2);
    expect(hit.headers["Deprecation"]).toBeDefined();
    expect(miss.headers["Deprecation"]).toBeUndefined();
  });
});
