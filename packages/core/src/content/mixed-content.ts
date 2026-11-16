/**
 * Mixed-content check: an https page that loads anything over plain http.
 *
 * A single `<script src="http://...">` undoes HTTPS: anyone on the network
 * path can rewrite that script and run code in the secure page's origin.
 * Browsers block such "blockable" content, so in practice the page is also
 * broken. This check finds the problem before users (or attackers) do.
 *
 * Pure: takes the HTML text and the page URL, never fetches the references.
 */
import { parseCsp } from "../csp.js";
import { makeFinding, Status, type Finding } from "../finding.js";
import type { HeaderMap } from "../headers.js";
import { normalizeAddress } from "../scan/address.js";
import {
  extractResources,
  type ExtractedHtml,
  type ResourceKind,
  type ResourceRef,
} from "./html.js";

export const MIXED_CONTENT_CHECK = "Mixed content";
export const MIXED_CONTENT_WEIGHT = 15;
/** How many offending URLs a finding's detail lists before summarising. */
export const MAX_EXAMPLES = 5;

export interface MixedContentRef extends ResourceRef {
  /** The absolute http: URL the browser would request. */
  readonly url: string;
}

export interface MixedContentInput {
  /** Final URL of the page (after redirects). */
  readonly pageUrl: string;
  /** Decoded HTML, or undefined when the response wasn't HTML. */
  readonly html: string | undefined;
  /** Response headers, for a CSP `upgrade-insecure-requests` directive. */
  readonly headers?: HeaderMap;
  /** True when only a prefix of the body was read. */
  readonly truncated?: boolean;
}

export interface MixedContentResult {
  readonly finding: Finding;
  readonly references: readonly MixedContentRef[];
  readonly upgradeInsecureRequests: boolean;
}

/**
 * Hosts the Secure Contexts spec treats as "potentially trustworthy" even
 * over http (localhost names and loopback IPs). Browsers don't flag them as
 * mixed content, so neither do we.
 */
export function isPotentiallyTrustworthyHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  const literal = normalizeAddress(host);
  if (!literal) return false;
  return literal.family === 4 ? literal.address.startsWith("127.") : literal.address === "::1";
}

/** Resolves `value` against `base`; undefined for unparseable URLs. */
function resolve(value: string, base: URL): URL | undefined {
  try {
    return new URL(value, base);
  } catch {
    return undefined;
  }
}

/**
 * Returns the references in `html` that resolve to insecure http: URLs.
 * Relative URLs resolve against `<base href>` when present, so an http base
 * turns every relative script into mixed content (and is reported itself).
 */
export function findMixedContent(html: string, pageUrl: string): MixedContentRef[] {
  return insecureReferences(extractResources(html), new URL(pageUrl));
}

function insecureReferences(extracted: ExtractedHtml, page: URL): MixedContentRef[] {
  const base =
    extracted.baseHref === undefined ? page : (resolve(extracted.baseHref, page) ?? page);
  const found: MixedContentRef[] = [];
  for (const ref of extracted.references) {
    // <base href> itself resolves against the document URL, not against itself.
    const url = resolve(ref.value, ref.tag === "base" ? page : base);
    if (url?.protocol !== "http:" || isPotentiallyTrustworthyHost(url.hostname)) continue;
    url.hash = "";
    found.push(Object.freeze({ ...ref, url: url.href }));
  }
  return found;
}

/** True if any enforced CSP (header or `<meta>`) contains `upgrade-insecure-requests`. */
export function hasUpgradeInsecureRequests(
  headers: HeaderMap | undefined,
  metaPolicies: readonly string[] = [],
): boolean {
  // Report-Only policies don't upgrade anything, so only the enforced header counts.
  const policies = [...(headers?.getAll("content-security-policy") ?? []), ...metaPolicies];
  return policies.some((serialized) =>
    serialized.split(",").some((policy) => parseCsp(policy).has("upgrade-insecure-requests")),
  );
}

function describe(refs: readonly MixedContentRef[]): string {
  const shown = refs.slice(0, MAX_EXAMPLES).map((r) => `<${r.tag} ${r.attribute}> ${r.url}`);
  const more = refs.length - shown.length;
  return shown.join("; ") + (more > 0 ? `; and ${String(more)} more` : "");
}

function byKind(refs: readonly MixedContentRef[], kind: ResourceKind): MixedContentRef[] {
  return refs.filter((r) => r.kind === kind);
}

/** Forms whose action stays on the page's own origin, which `upgrade-insecure-requests` upgrades. */
function sameHost(ref: MixedContentRef, page: URL): boolean {
  return new URL(ref.url).hostname === page.hostname;
}

const RECOMMEND_HTTPS =
  "Load every subresource over https:// (or a relative/protocol-relative URL), and add " +
  "`Content-Security-Policy: upgrade-insecure-requests` as a safety net.";

function notApplicable(detail: string): Finding {
  return makeFinding({ check: MIXED_CONTENT_CHECK, status: Status.Info, detail });
}

/**
 * Grades a page for mixed content (15 points):
 * - pass (15): https page with no insecure references;
 * - warn (10): only upgradeable media, or the issues are covered by `upgrade-insecure-requests`;
 * - fail (0): blockable content or an insecure form target that nothing upgrades.
 * Not-applicable cases (http page, non-HTML response) are informational.
 */
export function checkMixedContent(input: MixedContentInput): MixedContentResult {
  const page = new URL(input.pageUrl);
  const none = (finding: Finding, uir = false): MixedContentResult =>
    Object.freeze({ finding, references: Object.freeze([]), upgradeInsecureRequests: uir });

  if (page.protocol !== "https:") {
    return none(notApplicable("Page is not served over HTTPS, so mixed content doesn't apply"));
  }
  if (input.html === undefined) {
    return none(notApplicable("Response is not HTML; no subresources to inspect"));
  }

  const extracted = extractResources(input.html);
  const references = insecureReferences(extracted, page);
  const uir = hasUpgradeInsecureRequests(input.headers, extracted.metaCsp);
  const note = input.truncated ? " (only the first part of the page was inspected)" : "";
  const blockable = byKind(references, "blockable");
  // upgrade-insecure-requests upgrades same-origin navigations, so only those forms are covered.
  const unsafeForms = byKind(references, "form").filter((r) => !uir || !sameHost(r, page));

  let finding: Finding;
  if (references.length === 0) {
    finding = makeFinding({
      check: MIXED_CONTENT_CHECK,
      status: Status.Pass,
      detail: `No insecure (http://) subresources found${note}`,
      weight: MIXED_CONTENT_WEIGHT,
      score: MIXED_CONTENT_WEIGHT,
    });
  } else if (unsafeForms.length > 0 || (blockable.length > 0 && !uir)) {
    const what =
      unsafeForms.length > 0 && blockable.length === 0
        ? "Insecure form target"
        : "Active mixed content";
    finding = makeFinding({
      check: MIXED_CONTENT_CHECK,
      status: Status.Fail,
      detail: `${what}: ${describe([...unsafeForms, ...blockable])}${note}`,
      weight: MIXED_CONTENT_WEIGHT,
      score: 0,
      recommendation: RECOMMEND_HTTPS,
    });
  } else {
    const why = uir
      ? "insecure references are upgraded by upgrade-insecure-requests"
      : "browsers auto-upgrade these media requests (and break them if HTTPS is unavailable)";
    finding = makeFinding({
      check: MIXED_CONTENT_CHECK,
      status: Status.Warn,
      detail: `Insecure references, ${why}: ${describe(references)}${note}`,
      weight: MIXED_CONTENT_WEIGHT,
      score: 10,
      recommendation: "Change the remaining http:// URLs to https:// in the markup.",
    });
  }
  return Object.freeze({
    finding,
    references: Object.freeze(references),
    upgradeInsecureRequests: uir,
  });
}
