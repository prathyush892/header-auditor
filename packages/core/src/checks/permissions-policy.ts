import { makeFinding, Status, type Finding } from "../finding.js";
import type { HeaderMap } from "../headers.js";

export const PERMISSIONS_POLICY_HEADER = "Permissions-Policy";
const WEIGHT = 10;

/**
 * Presence check only, like the Python engine: any non-empty policy passes.
 * Grading individual features (camera, geolocation, …) is left for later
 * because the "right" allow-list depends on what the site actually uses.
 */
export function checkPermissionsPolicy(headers: HeaderMap): Finding {
  const check = PERMISSIONS_POLICY_HEADER;
  if (headers.get(PERMISSIONS_POLICY_HEADER)) {
    return makeFinding({
      check,
      status: Status.Pass,
      detail: "Present.",
      weight: WEIGHT,
      score: WEIGHT,
    });
  }
  return makeFinding({
    check,
    status: Status.Warn,
    detail: "Header missing.",
    weight: WEIGHT,
    recommendation: `Add e.g. \`${PERMISSIONS_POLICY_HEADER}: camera=(), microphone=(), geolocation=()\`.`,
  });
}
