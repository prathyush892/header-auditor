import { makeFinding, Status, type Finding } from "../finding.js";
import type { HeaderMap } from "../headers.js";

export const INFO_DISCLOSURE_CHECK = "Information disclosure";
const WEIGHT = 5;

/** Headers that commonly reveal the server stack, in reporting order. */
export const LEAKY_HEADERS = [
  "Server",
  "X-Powered-By",
  "X-AspNet-Version",
  "X-AspNetMvc-Version",
] as const;

const HAS_DIGIT = /\d/;

/**
 * A bare product name in `Server` ("nginx") is harmless and almost universal,
 * so it only counts as a leak when it carries a version (any digit). The other
 * headers exist only to advertise the stack, so any value counts.
 */
export function leakedHeaders(headers: HeaderMap): string[] {
  const leaks: string[] = [];
  for (const name of LEAKY_HEADERS) {
    const value = headers.get(name);
    if (!value) continue;
    if (name === "Server" && !HAS_DIGIT.test(value)) continue;
    leaks.push(`${name}: ${value}`);
  }
  return leaks;
}

export function checkInfoDisclosure(headers: HeaderMap): Finding {
  const check = INFO_DISCLOSURE_CHECK;
  const leaks = leakedHeaders(headers);
  if (leaks.length > 0) {
    return makeFinding({
      check,
      status: Status.Warn,
      detail: `Exposes ${leaks.join(", ")}.`,
      weight: WEIGHT,
      recommendation: "Remove version details from these headers.",
    });
  }
  return makeFinding({
    check,
    status: Status.Pass,
    detail: "No version-revealing headers.",
    weight: WEIGHT,
    score: WEIGHT,
  });
}
