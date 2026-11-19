/**
 * Subresource Integrity (SRI) check: are third-party scripts and stylesheets
 * pinned to a hash with `integrity="sha384-..."`?
 *
 * A `<script src="https://cdn.example/lib.js">` runs with the full authority
 * of the page that includes it. HTTPS only proves the bytes came from the CDN;
 * if the CDN (or the package it serves) is compromised, every site that loads
 * it runs the attacker's code. With an `integrity` attribute the browser
 * hashes what it received and refuses to run it when the hash doesn't match.
 *
 * Pure: reads the HTML text, never fetches the subresources, so it checks
 * that a well-formed hash is *present*, not that it matches the file.
 */
import { Buffer } from "node:buffer";
import { Parser } from "htmlparser2";
import { makeFinding, Status, type Finding } from "../finding.js";

export const SRI_CHECK = "Subresource Integrity";
export const SRI_WEIGHT = 10;
/** How many offending URLs a finding's detail lists before summarising. */
export const SRI_MAX_EXAMPLES = 5;
/** Upper bound on collected references; real pages have a few dozen. */
export const SRI_MAX_REFERENCES = 1000;

/** Hash algorithms browsers accept in `integrity`, with their digest sizes in bytes. */
export const SRI_ALGORITHMS: ReadonlyMap<string, number> = new Map([
  ["sha256", 32],
  ["sha384", 48],
  ["sha512", 64],
]);

export type SriResourceType = "script" | "stylesheet";

/**
 * - `protected`: valid integrity metadata, fetched in CORS mode, so the browser enforces it.
 * - `missing`: no integrity attribute.
 * - `invalid`: an integrity attribute with no usable hash; browsers ignore it entirely.
 * - `no-cors`: valid hash but no `crossorigin`; the browser can't check an opaque
 *   cross-origin response, so it *blocks* the resource (safe, but the page breaks).
 */
export type SriStatus = "protected" | "missing" | "invalid" | "no-cors";

export interface SriReference {
  /** "script" or "link". */
  readonly tag: string;
  readonly type: SriResourceType;
  /** Absolute URL (fragment removed). */
  readonly url: string;
  readonly host: string;
  /** The integrity attribute as written, if any. */
  readonly integrity: string | undefined;
  /** Recognised algorithms with a well-formed digest, strongest last. */
  readonly algorithms: readonly string[];
  /** The crossorigin attribute ("" means anonymous), if present. */
  readonly crossorigin: string | undefined;
  readonly status: SriStatus;
}

export interface SriInput {
  /** Final URL of the page (after redirects). */
  readonly pageUrl: string;
  /** Decoded HTML, or undefined when the response wasn't HTML. */
  readonly html: string | undefined;
  /** True when only a prefix of the body was read. */
  readonly truncated?: boolean;
  /** Extra hosts to treat as first-party (e.g. your own CDN on another domain). */
  readonly firstPartyHosts?: readonly string[];
}

export interface SriResult {
  readonly finding: Finding;
  /** Third-party scripts and stylesheets, in document order. */
  readonly references: readonly SriReference[];
}

/** A raw `<script src>` / `<link href>` tag that SRI applies to. */
interface RawTag {
  readonly tag: string;
  readonly type: SriResourceType;
  readonly value: string;
  readonly integrity: string | undefined;
  readonly crossorigin: string | undefined;
  /** Module scripts and modulepreload are always fetched in CORS mode. */
  readonly alwaysCors: boolean;
}

type Attributes = Readonly<Record<string, string>>;

/** `<script type>` values that the browser executes as classic JavaScript. */
const JS_MIME_TYPES = new Set([
  "",
  "text/javascript",
  "application/javascript",
  "application/ecmascript",
  "application/x-javascript",
  "text/ecmascript",
  "text/jscript",
  "module",
]);

function attr(attribs: Attributes, name: string): string | undefined {
  // A Map lookup avoids prototype keys like "constructor" on attacker-controlled markup.
  return new Map(Object.entries(attribs)).get(name);
}

function nonEmpty(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed === undefined || trimmed.length === 0 ? undefined : trimmed;
}

function tokens(value: string | undefined): string[] {
  return (value ?? "")
    .toLowerCase()
    .split(/[\t\n\f\r ]+/)
    .filter((t) => t.length > 0);
}

function scriptTag(attribs: Attributes): RawTag | undefined {
  const src = nonEmpty(attr(attribs, "src"));
  const type = (attr(attribs, "type") ?? "").trim().toLowerCase();
  // Inline scripts can't use SRI; data blocks (JSON, templates) aren't executed.
  if (src === undefined || !JS_MIME_TYPES.has(type)) return undefined;
  return {
    tag: "script",
    type: "script",
    value: src,
    integrity: attr(attribs, "integrity"),
    crossorigin: attr(attribs, "crossorigin"),
    alwaysCors: type === "module",
  };
}

function linkTag(attribs: Attributes): RawTag | undefined {
  const href = nonEmpty(attr(attribs, "href"));
  if (href === undefined) return undefined;
  const rels = tokens(attr(attribs, "rel"));
  const as = (attr(attribs, "as") ?? "").trim().toLowerCase();
  let type: SriResourceType | undefined;
  if (rels.includes("stylesheet")) type = "stylesheet";
  else if (rels.includes("modulepreload")) type = "script";
  else if (rels.includes("preload") && (as === "script" || as === "style")) {
    type = as === "script" ? "script" : "stylesheet";
  }
  if (type === undefined) return undefined;
  return {
    tag: "link",
    type,
    value: href,
    integrity: attr(attribs, "integrity"),
    crossorigin: attr(attribs, "crossorigin"),
    alwaysCors: rels.includes("modulepreload"),
  };
}

/** Script and stylesheet tags in `html` (bounded), plus the first `<base href>`. */
function extractTags(html: string): { tags: RawTag[]; baseHref: string | undefined } {
  const tags: RawTag[] = [];
  let baseHref: string | undefined;
  const parser = new Parser(
    {
      onopentag(name, attribs) {
        if (name === "base" && baseHref === undefined) baseHref = nonEmpty(attr(attribs, "href"));
        if (tags.length >= SRI_MAX_REFERENCES) return;
        const tag =
          name === "script" ? scriptTag(attribs) : name === "link" ? linkTag(attribs) : undefined;
        if (tag) tags.push(tag);
      },
    },
    { decodeEntities: true, lowerCaseTags: true, lowerCaseAttributeNames: true },
  );
  parser.write(html);
  parser.end();
  return { tags, baseHref };
}

const BASE64_DIGEST = /^[A-Za-z0-9+/_-]{1,128}={0,2}$/;

/**
 * Parses an `integrity` attribute (SRI §3.3.3) and returns the recognised
 * algorithms whose digest is well-formed base64 of the right length.
 * Unknown algorithms and options (`?foo`) are ignored, as browsers do. An
 * empty result means the browser treats the resource as unprotected.
 */
export function parseIntegrity(value: string | undefined): string[] {
  const algorithms: string[] = [];
  for (const token of (value ?? "").split(/[\t\n\f\r ]+/)) {
    const dash = token.indexOf("-");
    if (dash <= 0) continue;
    const algorithm = token.slice(0, dash);
    const digestSize = SRI_ALGORITHMS.get(algorithm);
    const digest = token.slice(dash + 1).split("?", 1)[0] ?? "";
    if (digestSize === undefined || !BASE64_DIGEST.test(digest)) continue;
    if (Buffer.from(digest, "base64").length !== digestSize) continue;
    if (!algorithms.includes(algorithm)) algorithms.push(algorithm);
  }
  const order = [...SRI_ALGORITHMS.keys()];
  return algorithms.sort((a, b) => order.indexOf(a) - order.indexOf(b));
}

function stripWww(host: string): string {
  return host.startsWith("www.") ? host.slice(4) : host;
}

/**
 * First-party means the page's own host, or a subdomain of it (with a leading
 * `www.` ignored, so `www.example.com` and `static.example.com` are one
 * party). This deliberately doesn't guess registrable domains without a
 * public-suffix list; other hosts you control go in `firstPartyHosts`.
 */
export function isFirstPartyHost(
  host: string,
  pageHost: string,
  extra: readonly string[] = [],
): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  const root = stripWww(pageHost.toLowerCase().replace(/\.$/, ""));
  if (extra.some((e) => e.toLowerCase().replace(/\.$/, "") === h)) return true;
  return h === root || h.endsWith(`.${root}`);
}

function resolve(value: string, base: URL): URL | undefined {
  try {
    return new URL(value, base);
  } catch {
    return undefined;
  }
}

function statusFor(tag: RawTag, algorithms: readonly string[]): SriStatus {
  if (tag.integrity === undefined) return "missing";
  if (algorithms.length === 0) return "invalid";
  if (tag.crossorigin === undefined && !tag.alwaysCors) return "no-cors";
  return "protected";
}

/**
 * Third-party scripts and stylesheets in `html` with their SRI status.
 * Same-origin and first-party subresources are skipped (their integrity is
 * only as good as the page's own), as are non-network URLs (`data:`, `blob:`).
 */
export function findSriReferences(
  html: string,
  pageUrl: string,
  firstPartyHosts: readonly string[] = [],
): SriReference[] {
  const page = new URL(pageUrl);
  const { tags, baseHref } = extractTags(html);
  const base = baseHref === undefined ? page : (resolve(baseHref, page) ?? page);
  const refs: SriReference[] = [];
  for (const tag of tags) {
    const url = resolve(tag.value, base);
    if (url === undefined || (url.protocol !== "https:" && url.protocol !== "http:")) continue;
    if (isFirstPartyHost(url.hostname, page.hostname, firstPartyHosts)) continue;
    url.hash = "";
    const algorithms = parseIntegrity(tag.integrity);
    refs.push(
      Object.freeze({
        tag: tag.tag,
        type: tag.type,
        url: url.href,
        host: url.hostname,
        integrity: tag.integrity,
        algorithms: Object.freeze(algorithms),
        crossorigin: tag.crossorigin,
        status: statusFor(tag, algorithms),
      }),
    );
  }
  return refs;
}

function describe(refs: readonly SriReference[]): string {
  const shown = refs
    .slice(0, SRI_MAX_EXAMPLES)
    .map((r) => `${r.type} ${r.url}${r.status === "invalid" ? " (unusable integrity value)" : ""}`);
  const more = refs.length - shown.length;
  return shown.join("; ") + (more > 0 ? `; and ${String(more)} more` : "");
}

const RECOMMEND_SRI =
  'Add integrity="sha384-<hash>" and crossorigin="anonymous" to every third-party ' +
  "<script> and <link rel=stylesheet>, pointing at a versioned URL. Generate the hash with " +
  "`openssl dgst -sha384 -binary file.js | openssl base64 -A`, or self-host the file.";

function grade(status: Status, score: number, detail: string, recommendation = ""): Finding {
  return makeFinding({
    check: SRI_CHECK,
    status,
    detail,
    weight: SRI_WEIGHT,
    score,
    recommendation,
  });
}

/**
 * Grades third-party subresource pinning (10 points):
 * - pass (10): no third-party scripts/stylesheets, or all carry a valid hash
 *   and are fetched in CORS mode;
 * - warn (8): every hash is valid but some lack `crossorigin`, so browsers block them;
 * - warn (5): scripts are pinned, but some stylesheets aren't (CSS can still
 *   restyle the page and leak data through selectors, but can't run code);
 * - fail (0): any third-party script without a usable hash.
 * A non-HTML response is informational.
 */
export function checkSubresourceIntegrity(input: SriInput): SriResult {
  if (input.html === undefined) {
    return Object.freeze({
      finding: makeFinding({
        check: SRI_CHECK,
        status: Status.Info,
        detail: "Response is not HTML; no subresources to inspect",
      }),
      references: Object.freeze([]),
    });
  }
  const references = findSriReferences(input.html, input.pageUrl, input.firstPartyHosts);
  const note = input.truncated ? " (only the first part of the page was inspected)" : "";
  const unpinned = references.filter((r) => r.status === "missing" || r.status === "invalid");
  const scripts = unpinned.filter((r) => r.type === "script");
  const noCors = references.filter((r) => r.status === "no-cors");

  let finding: Finding;
  if (references.length === 0) {
    finding = grade(Status.Pass, SRI_WEIGHT, `No third-party scripts or stylesheets${note}`);
  } else if (scripts.length > 0) {
    finding = grade(
      Status.Fail,
      0,
      `${String(scripts.length)} of ${String(references.length)} third-party resource(s) are ` +
        `scripts without Subresource Integrity: ${describe(scripts)}${note}`,
      RECOMMEND_SRI,
    );
  } else if (unpinned.length > 0) {
    finding = grade(
      Status.Warn,
      5,
      `Third-party stylesheets without Subresource Integrity: ${describe(unpinned)}${note}`,
      RECOMMEND_SRI,
    );
  } else if (noCors.length > 0) {
    finding = grade(
      Status.Warn,
      8,
      `Integrity set but crossorigin missing, so browsers block these: ${describe(noCors)}${note}`,
      'Add crossorigin="anonymous" so the browser fetches the file in CORS mode and can verify it.',
    );
  } else {
    finding = grade(
      Status.Pass,
      SRI_WEIGHT,
      `All ${String(references.length)} third-party script(s)/stylesheet(s) are pinned with ` +
        `Subresource Integrity${note}`,
    );
  }
  return Object.freeze({ finding, references: Object.freeze(references) });
}
