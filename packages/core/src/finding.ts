/**
 * The result type every check returns, mirroring the Python `Finding` dataclass.
 *
 * Field names are single words on purpose: the JSON produced here and by the
 * Python CLI's `--json` output have the same shape, so results from either
 * engine can be compared or stored side by side.
 */

export const Status = {
  Pass: "pass",
  Warn: "warn",
  Fail: "fail",
  Info: "info",
} as const;

export type Status = (typeof Status)[keyof typeof Status];

export interface Finding {
  /** Human-readable check name, usually the header it inspects. */
  readonly check: string;
  readonly status: Status;
  /** What was observed. */
  readonly detail: string;
  /** Points available for this check (0 for informational findings). */
  readonly weight: number;
  /** Points earned, always between 0 and `weight`. */
  readonly score: number;
  /** How to fix it; empty string when nothing needs fixing. */
  readonly recommendation: string;
}

export interface FindingInit {
  check: string;
  status: Status;
  detail: string;
  weight?: number;
  score?: number;
  recommendation?: string;
}

/**
 * Builds a frozen Finding and enforces the scoring invariant
 * (0 <= score <= weight, both integers) so a buggy check fails loudly in tests
 * instead of silently skewing the grade.
 */
export function makeFinding(init: FindingInit): Finding {
  const weight = init.weight ?? 0;
  const score = init.score ?? 0;
  if (!Number.isInteger(weight) || weight < 0) {
    throw new RangeError(`Finding "${init.check}": weight must be a non-negative integer`);
  }
  if (!Number.isInteger(score) || score < 0 || score > weight) {
    throw new RangeError(
      `Finding "${init.check}": score must be an integer in [0, ${String(weight)}]`,
    );
  }
  return Object.freeze({
    check: init.check,
    status: init.status,
    detail: init.detail,
    weight,
    score,
    recommendation: init.recommendation ?? "",
  });
}
