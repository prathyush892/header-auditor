import { defineConfig } from "vitest/config";

import { sourceResolve } from "../../vitest.shared.js";

export default defineConfig({
  ...sourceResolve,
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
    // PGlite (WASM Postgres) and a real redis-server start per suite.
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
});
