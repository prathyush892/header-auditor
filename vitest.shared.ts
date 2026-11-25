/**
 * Vitest settings shared by every workspace package.
 *
 * Workspace packages export their TypeScript source under the
 * `@header-auditor/source` condition (and built `dist/` for everyone else).
 * Tests resolve that condition, so `pnpm test` never needs a prior build and
 * always runs against the code on disk; `tsconfig.base.json` sets the same
 * condition for type checking.
 */
import type { ViteUserConfig } from "vitest/config";

export const SOURCE_CONDITION = "@header-auditor/source";

/**
 * Our condition first, then Vite's default server conditions. Replacing the
 * list (rather than only prepending) is how Vite's option works, and leaving
 * out "module" or adding "import" changes how CommonJS packages such as `pg`
 * resolve their own dependencies.
 */
const conditions = [SOURCE_CONDITION, "module", "node", "development|production"];

export const sourceResolve: Pick<ViteUserConfig, "resolve" | "ssr"> = {
  resolve: { conditions },
  ssr: { resolve: { conditions } },
};
