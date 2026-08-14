import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    env: {
      NEXTAUTH_SECRET: "test_secret_for_vitest_unit_runs",
    },
    testTimeout: 10000,
    hookTimeout: 10000,
    // Memory-isolated forks. The generated Prisma client (362 models) plus the
    // large service graph make module transform/collection memory-heavy, so we
    // spread files across several forks (each accumulates less) and cap per-fork
    // heap so the total stays well under host RAM. Previously a single 8 GB
    // heap per fork × maxForks exhausted a 16 GB host and killed workers
    // ("Worker exited unexpectedly"), which the run-tests-sequential.ps1 hack
    // worked around one-file-per-process. This runs the full suite in parallel.
    pool: "forks",
    poolOptions: {
      forks: {
        execArgv: ["--max-old-space-size=2048"],
        minForks: 1,
        maxForks: process.env.CI ? 2 : 4,
      },
    },
    exclude: process.env.CI
      ? ["**/node_modules/**", "**/dist/**", "**/*.coverage.spec.ts"]
      : ["**/node_modules/**", "**/dist/**"],
    coverage: {
      provider: "v8",
      // `json` emits coverage/coverage-final.json for tooling that consumes
      // machine-readable coverage.
      reporter: ["text", "json", "html"],
      reportsDirectory: "./coverage",
      // J02 — `all: true` so coverage counts untested source files and can
      // fail; thresholds set at the measured floor (ratchet may only rise).
      all: true,
      thresholds: {
        lines: 15,
        functions: 32,
        branches: 60,
        statements: 15,
      },
      exclude: [
        "src/**/*.spec.ts",
        "src/**/tests/**",
        "src/**/dto/**",
        "src/main.ts",
        "src/tracing.ts",
        "src/**/*.module.ts",
      ],
    },
  },
});
