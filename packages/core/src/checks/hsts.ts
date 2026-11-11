import { makeFinding, Status, type Finding } from "../finding.js";
import type { HeaderMap } from "../headers.js";

export const HSTS_HEADER = "Strict-Transport-Security";
export const ONE_YEAR_SECONDS = 31_536_000;
export const HALF_YEAR_SECONDS = 15_768_000;
const WEIGHT = 20;

/** Same pattern as the Python engine: optional quotes, any number of digits. */
const MAX_AGE = /max-age\s*=\s*"?(\d+)/i;

/**
 * Parses max-age as a BigInt so absurdly large values (which some servers do
 * send) are compared exactly instead of overflowing to Infinity or losing
 * precision, and are printed the same way Python's `int` prints them.
 */
export function parseMaxAge(value: string): bigint | undefined {
  const digits = MAX_AGE.exec(value)?.[1];
  return digits === undefined ? undefined : BigInt(digits);
}

export interface HstsOptions {
  /** HSTS is only meaningful on HTTPS responses; browsers ignore it over HTTP. */
  isHttps?: boolean;
}

export function checkHsts(headers: HeaderMap, { isHttps = true }: HstsOptions = {}): Finding {
  const check = HSTS_HEADER;
  if (!isHttps) {
    return makeFinding({
      check,
      status: Status.Info,
      detail: "Not applicable over plain HTTP; serve the site over HTTPS.",
    });
  }

  const value = headers.get(HSTS_HEADER);
  if (!value) {
    return makeFinding({
      check,
      status: Status.Fail,
      detail: "Header missing.",
      weight: WEIGHT,
      recommendation: `Add \`${HSTS_HEADER}: max-age=${String(ONE_YEAR_SECONDS)}; includeSubDomains\`.`,
    });
  }

  const age = parseMaxAge(value);
  if (age === undefined) {
    return makeFinding({
      check,
      status: Status.Fail,
      detail: `No valid max-age in '${value}'.`,
      weight: WEIGHT,
      recommendation: "Set max-age to at least one year.",
    });
  }

  if (age < BigInt(HALF_YEAR_SECONDS)) {
    return makeFinding({
      check,
      status: Status.Warn,
      detail: `max-age=${age.toString()} is shorter than 6 months.`,
      weight: WEIGHT,
      score: Math.floor(WEIGHT / 2),
      recommendation: `Raise max-age to ${String(ONE_YEAR_SECONDS)}.`,
    });
  }

  const detail = `max-age=${age.toString()}`;
  if (!value.toLowerCase().includes("includesubdomains")) {
    return makeFinding({
      check,
      status: Status.Warn,
      detail: `${detail} without includeSubDomains.`,
      weight: WEIGHT,
      score: WEIGHT - 5,
      recommendation: "Add includeSubDomains if all subdomains serve HTTPS.",
    });
  }

  return makeFinding({
    check,
    status: Status.Pass,
    detail: `${detail} with includeSubDomains.`,
    weight: WEIGHT,
    score: WEIGHT,
  });
}
