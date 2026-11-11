import { makeFinding, Status, type Finding } from "../finding.js";
import type { HeaderMap } from "../headers.js";

export const REFERRER_POLICY_HEADER = "Referrer-Policy";
const WEIGHT = 10;
const RECOMMENDED = "strict-origin-when-cross-origin";

/** Policies that never send the full URL (path + query) to another origin. */
export const SAFE_REFERRER_POLICIES: ReadonlySet<string> = new Set([
  "no-referrer",
  "same-origin",
  "strict-origin",
  "strict-origin-when-cross-origin",
]);

/**
 * The header may list fallbacks ("no-referrer, strict-origin-when-cross-origin");
 * browsers apply the last one, so that is the one graded.
 */
export function effectiveReferrerPolicy(value: string): string | undefined {
  const tokens = value
    .split(",")
    .map((t) => t.trim().toLowerCase())
    .filter((t) => t.length > 0);
  return tokens.at(-1);
}

export function checkReferrerPolicy(headers: HeaderMap): Finding {
  const check = REFERRER_POLICY_HEADER;
  const value = headers.get(REFERRER_POLICY_HEADER);
  if (!value) {
    return makeFinding({
      check,
      status: Status.Warn,
      detail: "Header missing (browser default applies).",
      weight: WEIGHT,
      score: 5,
      recommendation: `Add \`${REFERRER_POLICY_HEADER}: ${RECOMMENDED}\`.`,
    });
  }

  const policy = effectiveReferrerPolicy(value);
  if (policy === undefined) {
    // e.g. "," — present but contains no policy token, so the browser default applies.
    return makeFinding({
      check,
      status: Status.Warn,
      detail: `No policy token in '${value}' (browser default applies).`,
      weight: WEIGHT,
      score: 5,
      recommendation: `Use ${RECOMMENDED}.`,
    });
  }
  if (SAFE_REFERRER_POLICIES.has(policy)) {
    return makeFinding({
      check,
      status: Status.Pass,
      detail: `${policy}.`,
      weight: WEIGHT,
      score: WEIGHT,
    });
  }
  if (policy === "unsafe-url") {
    return makeFinding({
      check,
      status: Status.Fail,
      detail: "unsafe-url leaks full URLs to every site.",
      weight: WEIGHT,
      recommendation: `Use ${RECOMMENDED}.`,
    });
  }
  return makeFinding({
    check,
    status: Status.Warn,
    detail: `'${policy}' can leak path data.`,
    weight: WEIGHT,
    score: 5,
    recommendation: `Use ${RECOMMENDED}.`,
  });
}
