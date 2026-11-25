import { defineConfig } from "vitest/config";

import { sourceResolve } from "../../vitest.shared.js";

export default defineConfig({
  ...sourceResolve,
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
    // The store contract suite boots PGlite (WASM Postgres); give slow CI room.
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
});
