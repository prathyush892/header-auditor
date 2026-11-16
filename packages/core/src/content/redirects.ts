/**
 * Pure checks over a redirect chain (the `RedirectHop[]` that `scanUrl()`
 * records):
 *
 * - `checkRedirectChain`: did any hop go from https back down to http?
 * - `analyzeHttpsRedirect`: when someone types the bare `http://` address, are
 *   they sent to HTTPS, on the same host, with a permanent redirect?
 *
 * The network side lives in `probe-redirect.ts`; everything here is
 * deterministic and tested with plain fixtures.
 */
import { makeFinding, Status, type Finding } from "../finding.js";
import type { RedirectHop } from "../scan/scan-url.js";
import type { ScanErrorCode } from "../scan/errors.js";

export const REDIRECT_CHAIN_CHECK = "Redirect chain";
export const REDIRECT_CHAIN_WEIGHT = 10;
export const HTTPS_REDIRECT_CHECK = "HTTP to HTTPS redirect";
export const HTTPS_REDIRECT_WEIGHT = 15;

/** Redirect statuses browsers and caches treat as permanent. */
export const PERMANENT_REDIRECTS: ReadonlySet<number> = new Set([301, 308]);

function protocolOf(url: string): string {
  return new URL(url).protocol;
}

/** Hops that leave https for http, in chain order. */
export function findDowngrades(redirects: readonly RedirectHop[]): RedirectHop[] {
  return redirects.filter(
    (hop) => protocolOf(hop.url) === "https:" && protocolOf(hop.location) === "http:",
  );
}

/**
 * Fails (0/10) when any redirect downgrades https → http: that hop is where an
 * attacker on the network can take over the navigation (SSL stripping).
 * No redirects at all is informational.
 */
export function checkRedirectChain(redirects: readonly RedirectHop[]): Finding {
  if (redirects.length === 0) {
    return makeFinding({
      check: REDIRECT_CHAIN_CHECK,
      status: Status.Info,
      detail: "No redirects were followed",
    });
  }
  const downgrades = findDowngrades(redirects);
  if (downgrades.length > 0) {
    const hops = downgrades.map((h) => `${h.url} → ${h.location}`).join("; ");
    return makeFinding({
      check: REDIRECT_CHAIN_CHECK,
      status: Status.Fail,
      detail: `HTTPS → HTTP downgrade in the redirect chain: ${hops}`,
      weight: REDIRECT_CHAIN_WEIGHT,
      score: 0,
      recommendation:
        "Make every Location header point at an https:// URL; never redirect from HTTPS to HTTP.",
    });
  }
  return makeFinding({
    check: REDIRECT_CHAIN_CHECK,
    status: Status.Pass,
    detail: `${String(redirects.length)} redirect(s), none downgrade to HTTP`,
    weight: REDIRECT_CHAIN_WEIGHT,
    score: REDIRECT_CHAIN_WEIGHT,
  });
}

/** What happened when the plain-http address was requested. */
export type HttpObservation =
  | {
      readonly kind: "response";
      /** Redirects followed, starting with the http:// request. */
      readonly redirects: readonly RedirectHop[];
      readonly finalUrl: string;
      readonly statusCode: number;
    }
  | {
      readonly kind: "error";
      /** Redirects followed before the failure. */
      readonly redirects: readonly RedirectHop[];
      readonly code: ScanErrorCode;
      /** The hop that failed. */
      readonly failedUrl: string;
    };

const RECOMMEND_REDIRECT =
  "Answer every http:// request with `301 Moved Permanently` (or 308) to the same host over " +
  "https://, then send HSTS from the https response.";

function finding(status: Status, score: number, detail: string, recommendation = ""): Finding {
  return makeFinding({
    check: HTTPS_REDIRECT_CHECK,
    status,
    detail,
    weight: HTTPS_REDIRECT_WEIGHT,
    score,
    recommendation,
  });
}

/** Grades the case where the very first hop already went to https. */
function gradeDirectUpgrade(first: RedirectHop, httpUrl: URL): Finding {
  const target = new URL(first.location);
  if (target.hostname !== httpUrl.hostname) {
    return finding(
      Status.Warn,
      8,
      `Redirects to HTTPS on a different host (${target.host}); HSTS can never be set for ` +
        `${httpUrl.hostname} because the browser never sees it over HTTPS`,
      "Redirect to https:// on the same host first, then on to the canonical host.",
    );
  }
  if (!PERMANENT_REDIRECTS.has(first.statusCode)) {
    return finding(
      Status.Warn,
      10,
      `Redirects to HTTPS with a temporary ${String(first.statusCode)}; browsers re-request ` +
        "http:// on every visit",
      "Use 301 or 308 so browsers and caches remember the upgrade.",
    );
  }
  return finding(
    Status.Pass,
    HTTPS_REDIRECT_WEIGHT,
    `${String(first.statusCode)} redirect from ${httpUrl.href} to ${first.location}`,
  );
}

/**
 * Grades how the http:// address of a site behaves (15 points).
 *
 * - pass: first hop is a permanent redirect to https on the same host;
 * - warn: HTTPS is reached, but via a temporary redirect, another host,
 *   extra plain-http hops, or the HTTPS side then failed;
 * - fail: http serves content or never reaches https, or a hop downgrades back;
 * - info (unscored): nothing listens on http at all, so nothing is exposed in clear text.
 */
export function analyzeHttpsRedirect(httpUrl: URL, observation: HttpObservation): Finding {
  const { redirects } = observation;
  const first = redirects[0];

  if (first === undefined) {
    if (observation.kind === "error") {
      return makeFinding({
        check: HTTPS_REDIRECT_CHECK,
        status: Status.Info,
        detail: `Nothing answered on ${httpUrl.href} (${observation.code}); visitors typing the bare domain get an error instead of an upgrade`,
        recommendation: RECOMMEND_REDIRECT,
      });
    }
    return finding(
      Status.Fail,
      0,
      `${httpUrl.href} answers ${String(observation.statusCode)} over plain HTTP without redirecting to HTTPS`,
      RECOMMEND_REDIRECT,
    );
  }

  const downgrades = findDowngrades(redirects);
  if (downgrades.length > 0) {
    const hop = downgrades[0];
    return finding(
      Status.Fail,
      0,
      `Redirect chain goes back to HTTP (${hop?.url ?? ""} → ${hop?.location ?? ""})`,
      RECOMMEND_REDIRECT,
    );
  }

  const upgradeIndex = redirects.findIndex((hop) => protocolOf(hop.location) === "https:");
  if (upgradeIndex === -1) {
    return finding(
      Status.Fail,
      0,
      `Followed ${String(redirects.length)} redirect(s) from ${httpUrl.href} but never reached HTTPS`,
      RECOMMEND_REDIRECT,
    );
  }

  let result =
    upgradeIndex === 0
      ? gradeDirectUpgrade(first, httpUrl)
      : finding(
          Status.Warn,
          8,
          `Reaches HTTPS only after ${String(upgradeIndex)} more plain-HTTP redirect(s); each one is interceptable`,
          "Redirect straight from http:// to https:// on the first hop.",
        );

  if (observation.kind === "error") {
    const score = Math.min(result.score, 8);
    result = finding(
      Status.Warn,
      score,
      `${result.detail}, but the HTTPS request then failed (${observation.code} at ${observation.failedUrl})`,
      result.recommendation || "Fix the HTTPS endpoint the redirect points to.",
    );
  }
  return result;
}
