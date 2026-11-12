import {
  effectiveScriptSources,
  findAnyOriginSource,
  hasSource,
  neutralizesUnsafeInline,
  parseCsp,
  type CspPolicy,
} from "../csp.js";
import { makeFinding, Status, type Finding } from "../finding.js";
import type { HeaderMap } from "../headers.js";

export const CSP_HEADER = "Content-Security-Policy";
export const CSP_REPORT_ONLY_HEADER = "Content-Security-Policy-Report-Only";
const WEIGHT = 25;
const PENALTY_PER_PROBLEM = 7;
const MIN_SCORE_WITH_POLICY = 5;
const STARTER_POLICY =
  "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'";

/** Lists the weaknesses in a parsed policy, in a stable order. */
export function cspProblems(policy: CspPolicy): string[] {
  const problems: string[] = [];
  const scriptSources = effectiveScriptSources(policy) ?? [];

  if (hasSource(scriptSources, "'unsafe-inline'") && !neutralizesUnsafeInline(scriptSources)) {
    problems.push("script-src allows 'unsafe-inline'");
  }
  if (hasSource(scriptSources, "'unsafe-eval'")) {
    problems.push("script-src allows 'unsafe-eval'");
  }
  // With 'strict-dynamic', CSP3 browsers ignore host and scheme sources, so a
  // wildcard kept as a fallback for old browsers doesn't widen the policy.
  const anyOrigin = hasSource(scriptSources, "'strict-dynamic'")
    ? undefined
    : findAnyOriginSource(scriptSources);
  if (anyOrigin !== undefined) {
    problems.push(`script-src allows any origin (${anyOrigin})`);
  }
  if (!policy.has("default-src") && !policy.has("script-src")) {
    problems.push("no default-src or script-src");
  }
  if (!policy.has("object-src") && !hasSource(policy.get("default-src") ?? [], "'none'")) {
    problems.push("object-src not restricted");
  }
  return problems;
}

export function checkCsp(headers: HeaderMap): Finding {
  const check = CSP_HEADER;
  const value = headers.get(CSP_HEADER);
  if (!value) {
    if (headers.get(CSP_REPORT_ONLY_HEADER)) {
      return makeFinding({
        check,
        status: Status.Warn,
        detail: "Only a Report-Only policy is set; nothing is enforced.",
        weight: WEIGHT,
        score: 5,
        recommendation: "Enforce the policy once reports are clean.",
      });
    }
    return makeFinding({
      check,
      status: Status.Fail,
      detail: "Header missing.",
      weight: WEIGHT,
      recommendation: `Start with \`${STARTER_POLICY}\`.`,
    });
  }

  const problems = cspProblems(parseCsp(value));
  if (problems.length === 0) {
    return makeFinding({
      check,
      status: Status.Pass,
      detail: "Policy present with no obvious weaknesses.",
      weight: WEIGHT,
      score: WEIGHT,
    });
  }
  return makeFinding({
    check,
    status: Status.Warn,
    detail: `${problems.join("; ")}.`,
    weight: WEIGHT,
    score: Math.max(MIN_SCORE_WITH_POLICY, WEIGHT - PENALTY_PER_PROBLEM * problems.length),
    recommendation:
      "Tighten the policy: prefer nonces/hashes over 'unsafe-inline' and set object-src 'none'.",
  });
}
