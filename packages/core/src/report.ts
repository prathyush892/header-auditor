/**
 * Scoring and grading: runs every check and turns the findings into a
 * 0–100 score and a letter grade, matching the Python `Report` class.
 */
import {
  checkContentTypeOptions,
  checkCookies,
  checkCoop,
  checkCsp,
  checkFraming,
  checkHsts,
  checkInfoDisclosure,
  checkPermissionsPolicy,
  checkReferrerPolicy,
} from "./checks/index.js";
import type { Finding } from "./finding.js";
import type { HeaderMap } from "./headers.js";

export type Grade = "A" | "B" | "C" | "D" | "F";

/** Lowest score that earns each grade, best first; anything lower is an F. */
export const GRADE_CUTOFFS: readonly (readonly [minScore: number, grade: Grade])[] = [
  [90, "A"],
  [75, "B"],
  [60, "C"],
  [40, "D"],
];

export interface RunOptions {
  /** Whether the audited response came over HTTPS (affects HSTS and cookies). */
  isHttps: boolean;
}

/** Runs every check in the same order as the Python `run_all`. */
export function runAll(headers: HeaderMap, { isHttps }: RunOptions): Finding[] {
  return [
    checkHsts(headers, { isHttps }),
    checkCsp(headers),
    checkFraming(headers),
    checkContentTypeOptions(headers),
    checkReferrerPolicy(headers),
    checkPermissionsPolicy(headers),
    checkCoop(headers),
    checkInfoDisclosure(headers),
    checkCookies(headers, { isHttps }),
  ];
}

/**
 * round(numerator / denominator) with ties going to the even neighbour —
 * the rule Python's built-in `round` uses. Done in integer arithmetic so the
 * result never depends on floating-point error, and so 2.5 rounds to 2 here
 * exactly as it does in the Python CLI (Math.round would give 3).
 */
export function roundHalfEven(numerator: number, denominator: number): number {
  if (!Number.isSafeInteger(numerator) || numerator < 0) {
    throw new RangeError("numerator must be a non-negative safe integer");
  }
  if (!Number.isSafeInteger(denominator) || denominator <= 0) {
    throw new RangeError("denominator must be a positive safe integer");
  }
  const quotient = Math.floor(numerator / denominator);
  const twiceRemainder = 2 * (numerator - quotient * denominator);
  if (twiceRemainder > denominator) return quotient + 1;
  if (twiceRemainder < denominator) return quotient;
  return quotient % 2 === 0 ? quotient : quotient + 1;
}

export interface Score {
  /** Points earned across all findings. */
  readonly earned: number;
  /** Points available across all findings (informational findings add 0). */
  readonly maxScore: number;
  /** Earned points as a percentage of maxScore, 0–100; 0 when nothing was graded. */
  readonly score: number;
  readonly grade: Grade;
}

export function gradeFor(score: number): Grade {
  for (const [minScore, grade] of GRADE_CUTOFFS) {
    if (score >= minScore) return grade;
  }
  return "F";
}

/** Percentage of available points earned, normalised over the checks that applied. */
export function scoreFindings(findings: readonly Finding[]): Score {
  let earned = 0;
  let maxScore = 0;
  for (const f of findings) {
    earned += f.score;
    maxScore += f.weight;
  }
  const score = maxScore === 0 ? 0 : roundHalfEven(100 * earned, maxScore);
  return { earned, maxScore, score, grade: gradeFor(score) };
}

export interface Report extends Score {
  /** Final URL after redirects. */
  readonly url: string;
  readonly statusCode: number;
  readonly findings: readonly Finding[];
}

export function buildReport(url: string, statusCode: number, findings: readonly Finding[]): Report {
  if (!Number.isInteger(statusCode) || statusCode < 100 || statusCode > 599) {
    throw new RangeError(
      `statusCode must be an HTTP status code (100-599), got ${String(statusCode)}`,
    );
  }
  return Object.freeze({
    url,
    statusCode,
    findings: Object.freeze([...findings]),
    ...scoreFindings(findings),
  });
}

/** Wire format shared with the Python CLI's `--json` output (`Report.to_dict`). */
export interface ReportJson {
  url: string;
  status_code: number;
  score: number;
  grade: Grade;
  findings: Finding[];
}

export function reportToJson(report: Report): ReportJson {
  return {
    url: report.url,
    status_code: report.statusCode,
    score: report.score,
    grade: report.grade,
    findings: report.findings.map((f) => ({ ...f })),
  };
}
