import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["**/*.itest.ts"],
    env: {
      NEXTAUTH_SECRET: "itest_secret",
      DATABASE_URL:
        "postgresql://unerp:unerp_password@localhost:5432/unerp_dev?schema=public",
    },
    testTimeout: 30000,
    hookTimeout: 30000,
    pool: "forks",
  },
});
