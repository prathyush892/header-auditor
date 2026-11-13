import { makeFinding, Status, type Finding } from "../finding.js";
import type { HeaderMap } from "../headers.js";

export const COOP_HEADER = "Cross-Origin-Opener-Policy";
const WEIGHT = 5;

/** Values that put the document in its own browsing-context group. */
export const SAFE_COOP_VALUES: ReadonlySet<string> = new Set([
  "same-origin",
  "same-origin-allow-popups",
]);

/**
 * COOP is a structured-header token that may carry parameters
 * (`same-origin; report-to="coop"`). Only the token decides the policy, so
 * parameters are dropped before comparing.
 */
export function coopToken(value: string): string {
  return (value.split(";", 1)[0] ?? "").trim().toLowerCase();
}

export function checkCoop(headers: HeaderMap): Finding {
  const check = COOP_HEADER;
  const token = coopToken(headers.get(COOP_HEADER) ?? "");
  if (SAFE_COOP_VALUES.has(token)) {
    return makeFinding({
      check,
      status: Status.Pass,
      detail: `${token}.`,
      weight: WEIGHT,
      score: WEIGHT,
    });
  }
  return makeFinding({
    check,
    status: Status.Warn,
    detail: "Missing or permissive.",
    weight: WEIGHT,
    recommendation: `Add \`${COOP_HEADER}: same-origin\`.`,
  });
}
