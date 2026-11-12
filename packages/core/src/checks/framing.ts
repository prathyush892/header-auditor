import { findAnyOriginSource, parseCsp } from "../csp.js";
import { makeFinding, Status, type Finding } from "../finding.js";
import type { HeaderMap } from "../headers.js";
import { CSP_HEADER } from "./csp.js";

export const FRAMING_CHECK = "Clickjacking protection";
export const X_FRAME_OPTIONS_HEADER = "X-Frame-Options";
const WEIGHT = 15;
const SAFE_XFO: ReadonlySet<string> = new Set(["DENY", "SAMEORIGIN"]);

/**
 * Grades clickjacking protection. CSP `frame-ancestors` wins over
 * X-Frame-Options when both are present (that's how browsers resolve it), so
 * it is inspected first. Report-Only policies are ignored: frame-ancestors is
 * never enforced from them.
 */
export function checkFraming(headers: HeaderMap): Finding {
  const check = FRAMING_CHECK;
  const csp = headers.get(CSP_HEADER);
  const ancestors = csp === undefined ? undefined : parseCsp(csp).get("frame-ancestors");

  if (ancestors !== undefined) {
    const anyOrigin = findAnyOriginSource(ancestors);
    if (anyOrigin !== undefined) {
      return makeFinding({
        check,
        status: Status.Fail,
        detail: `CSP frame-ancestors allows any origin (${anyOrigin}).`,
        weight: WEIGHT,
        recommendation: "Use frame-ancestors 'self' or 'none'.",
      });
    }
    // An empty source list matches nothing, i.e. it behaves like 'none'.
    const shown = ancestors.length > 0 ? ancestors.join(" ") : "(empty, same as 'none')";
    return makeFinding({
      check,
      status: Status.Pass,
      detail: `CSP frame-ancestors ${shown}.`,
      weight: WEIGHT,
      score: WEIGHT,
    });
  }

  const xfo = (headers.get(X_FRAME_OPTIONS_HEADER) ?? "").toUpperCase();
  if (SAFE_XFO.has(xfo)) {
    return makeFinding({
      check,
      status: Status.Pass,
      detail: `X-Frame-Options: ${xfo}.`,
      weight: WEIGHT,
      score: WEIGHT,
    });
  }
  if (xfo) {
    return makeFinding({
      check,
      status: Status.Warn,
      detail: `Unsupported X-Frame-Options value '${xfo}'.`,
      weight: WEIGHT,
      score: 5,
      recommendation: "Use DENY or SAMEORIGIN, or CSP frame-ancestors.",
    });
  }
  return makeFinding({
    check,
    status: Status.Fail,
    detail: "No X-Frame-Options or CSP frame-ancestors.",
    weight: WEIGHT,
    recommendation: "Add `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`.",
  });
}
