/**
 * Conversions between packages/core results and database rows.
 *
 * The engine uses lower-case string unions ("pass", "A"); the database uses
 * Postgres enums (PASS, A). Mapping happens in one place so the worker never
 * hand-builds rows, and every value is validated on the way in: the CHECK
 * constraints in the migration are the last line of defence, not the first.
 *
 * `EngineFinding` is structural on purpose: it matches core's `Finding`
 * without making this package depend on core's build output.
 */
import {
  FindingCategory,
  FindingStatus,
  Grade,
  type FindingCategory as FindingCategoryT,
  type FindingStatus as FindingStatusT,
  type Grade as GradeT,
} from "./generated/prisma/enums.js";

export interface EngineFinding {
  readonly check: string;
  readonly status: "pass" | "warn" | "fail" | "info";
  readonly detail: string;
  readonly weight: number;
  readonly score: number;
  readonly recommendation: string;
}

export type EngineGrade = "A" | "B" | "C" | "D" | "F";

/** Row shape for `prisma.finding.createMany({ data })`, minus `scanId`. */
export interface FindingRow {
  category: FindingCategoryT;
  check: string;
  status: FindingStatusT;
  detail: string;
  weight: number;
  score: number;
  recommendation: string;
  position: number;
}

/** Column limits from the migration; enforced here so errors are readable. */
export const CHECK_NAME_MAX_LENGTH = 100;
/** SMALLINT upper bound. */
const SMALLINT_MAX = 32_767;

const STATUS_TO_DB: ReadonlyMap<string, FindingStatusT> = new Map([
  ["pass", FindingStatus.PASS],
  ["warn", FindingStatus.WARN],
  ["fail", FindingStatus.FAIL],
  ["info", FindingStatus.INFO],
]);

const STATUS_FROM_DB: ReadonlyMap<FindingStatusT, EngineFinding["status"]> = new Map(
  [...STATUS_TO_DB].map(([engine, db]) => [db, engine as EngineFinding["status"]]),
);

const GRADES: ReadonlySet<string> = new Set(Object.values(Grade));

export function toDbFindingStatus(status: string): FindingStatusT {
  // A Map, not an object lookup, so "__proto__" or "toString" can't match.
  const mapped = STATUS_TO_DB.get(status);
  if (mapped === undefined) {
    throw new RangeError(`Unknown finding status: ${JSON.stringify(status)}`);
  }
  return mapped;
}

export function fromDbFindingStatus(status: FindingStatusT): EngineFinding["status"] {
  const mapped = STATUS_FROM_DB.get(status);
  if (mapped === undefined) throw new RangeError(`Unknown database status: ${status}`);
  return mapped;
}

export function toDbGrade(grade: string): GradeT {
  if (!GRADES.has(grade)) {
    throw new RangeError(`Unknown grade: ${JSON.stringify(grade)}`);
  }
  return grade as GradeT;
}

export function toDbScore(score: number): number {
  if (!Number.isInteger(score) || score < 0 || score > 100) {
    throw new RangeError(`Scan score must be an integer in [0, 100], got ${String(score)}`);
  }
  return score;
}

/**
 * Postgres text columns reject NUL bytes ("invalid byte sequence"), and
 * finding details can quote attacker-controlled bytes from the scanned site.
 * Stripping them keeps a hostile target from making its own scan unsavable.
 */
export function stripNul(value: string): string {
  return value.replaceAll("\u0000", "");
}

function checkFinding(f: EngineFinding, index: number): void {
  const label = `Finding #${String(index)} (${JSON.stringify(f.check.slice(0, 40))})`;
  if (f.check.trim() === "" || f.check.length > CHECK_NAME_MAX_LENGTH) {
    throw new RangeError(`${label}: check name must be 1-${String(CHECK_NAME_MAX_LENGTH)} chars`);
  }
  if (!Number.isInteger(f.weight) || f.weight < 0 || f.weight > SMALLINT_MAX) {
    throw new RangeError(`${label}: weight must be a non-negative integer`);
  }
  if (!Number.isInteger(f.score) || f.score < 0 || f.score > f.weight) {
    throw new RangeError(`${label}: score must be an integer in [0, weight]`);
  }
}

/**
 * Converts engine findings from one or more report sections into rows,
 * numbering `position` across all sections so the report renders in order.
 */
export function findingRows(
  sections: readonly (readonly [FindingCategoryT, readonly EngineFinding[]])[],
): FindingRow[] {
  const rows: FindingRow[] = [];
  for (const [category, findings] of sections) {
    if (!Object.hasOwn(FindingCategory, category)) {
      throw new RangeError(`Unknown finding category: ${JSON.stringify(category)}`);
    }
    for (const f of findings) {
      checkFinding(f, rows.length);
      if (rows.length >= SMALLINT_MAX) throw new RangeError("Too many findings for one scan");
      rows.push({
        category,
        check: stripNul(f.check),
        status: toDbFindingStatus(f.status),
        detail: stripNul(f.detail),
        weight: f.weight,
        score: f.score,
        recommendation: stripNul(f.recommendation),
        position: rows.length,
      });
    }
  }
  return rows;
}
