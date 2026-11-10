/**
 * @header-auditor/core — the TypeScript scan engine.
 *
 * This package is intentionally empty of checks for now: roadmap step 2 ports
 * the first Python checks here. It exists today so the workspace, type
 * checking, linting and tests are wired up end to end before real code lands.
 */

/** Semantic version of the scan engine, reported alongside every scan result. */
export const ENGINE_VERSION = "0.0.0";

/** Identifies which engine produced a result (the Python CLI or this package). */
export type EngineName = "header-auditor-core" | "header-auditor-python";

export const ENGINE_NAME: EngineName = "header-auditor-core";
