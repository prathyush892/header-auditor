import { makeFinding, Status, type Finding } from "../finding.js";
import type { HeaderMap } from "../headers.js";

export const CONTENT_TYPE_OPTIONS_HEADER = "X-Content-Type-Options";
const WEIGHT = 10;

/** `nosniff` stops browsers from guessing a response's MIME type (e.g. running an upload as script). */
export function checkContentTypeOptions(headers: HeaderMap): Finding {
  const check = CONTENT_TYPE_OPTIONS_HEADER;
  const value = (headers.get(CONTENT_TYPE_OPTIONS_HEADER) ?? "").toLowerCase();

  if (value === "nosniff") {
    return makeFinding({
      check,
      status: Status.Pass,
      detail: "nosniff.",
      weight: WEIGHT,
      score: WEIGHT,
    });
  }
  if (value) {
    return makeFinding({
      check,
      status: Status.Warn,
      detail: `Unexpected value '${value}'.`,
      weight: WEIGHT,
      score: 3,
      recommendation: "Set to `nosniff`.",
    });
  }
  return makeFinding({
    check,
    status: Status.Fail,
    detail: "Header missing.",
    weight: WEIGHT,
    recommendation: `Add \`${CONTENT_TYPE_OPTIONS_HEADER}: nosniff\`.`,
  });
}
