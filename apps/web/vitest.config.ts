import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

import { sourceResolve } from "../../vitest.shared.js";

export default defineConfig({
  ...sourceResolve,
  resolve: {
    ...sourceResolve.resolve,
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
});
