/**
 * Extracts the URLs an HTML document would make the browser *load* (scripts,
 * stylesheets, frames, images, media, form targets) so the mixed-content
 * check can look for plain-http ones. Nothing here fetches anything: the
 * references are only strings to classify.
 *
 * Parsing uses htmlparser2, a tolerant streaming tokenizer, rather than
 * regexes, so comments, `<script>` bodies, attribute quoting and entity
 * encoding (`&#104;ttp:`) are handled the way a browser tokenizes them.
 */
import { Parser } from "htmlparser2";

/**
 * How a browser treats an insecure reference on an https page (W3C Mixed
 * Content Level 2):
 * - `blockable`: scripts, styles, frames, plugins, fonts via CSS... blocked outright.
 * - `upgradeable`: `<img>`, `<audio>`, `<video>` are rewritten to https and
 *   blocked if that fails, so they break instead of leaking.
 * - `form`: a form that *submits* to http sends the user's input in clear text.
 */
export type ResourceKind = "blockable" | "upgradeable" | "form";

export interface ResourceRef {
  /** Lowercased element name, or "style" for CSS `url()`/`@import`. */
  readonly tag: string;
  /** Attribute the URL came from, or "css" for stylesheet text. */
  readonly attribute: string;
  /** The URL exactly as written (entities decoded), before resolution. */
  readonly value: string;
  readonly kind: ResourceKind;
}

export interface ExtractedHtml {
  readonly references: readonly ResourceRef[];
  /** href of the first `<base>` element, which every relative URL resolves against. */
  readonly baseHref: string | undefined;
  /** Policies from `<meta http-equiv="Content-Security-Policy">`. */
  readonly metaCsp: readonly string[];
}

type Attributes = Readonly<Record<string, string>>;

/** Media elements whose own `src` is auto-upgraded (Mixed Content L2 §4.1). */
const UPGRADEABLE_TAGS = new Set(["img", "audio", "video"]);

/** `<link rel>` values that make the browser fetch the href as a subresource. */
const FETCHING_LINK_RELS = new Set([
  "stylesheet",
  "modulepreload",
  "preload",
  "prefetch",
  "icon",
  "apple-touch-icon",
  "manifest",
]);

/** Element → attributes holding a single URL that is fetched as a blockable subresource. */
const BLOCKABLE_URL_ATTRIBUTES: ReadonlyMap<string, readonly string[]> = new Map([
  ["script", ["src"]],
  ["iframe", ["src"]],
  ["frame", ["src"]],
  ["embed", ["src"]],
  ["object", ["data"]],
  ["track", ["src"]],
  ["base", ["href"]],
]);

const FORM_URL_ATTRIBUTES: ReadonlyMap<string, readonly string[]> = new Map([
  ["form", ["action"]],
  ["button", ["formaction"]],
  ["input", ["formaction"]],
]);

/** CSS `url(...)` and `@import "..."` targets. Bounded quantifiers keep it linear. */
const CSS_URL = /url\(\s{0,16}(["']?)([^"')\s]{1,2048})\1\s{0,16}\)/gi;
const CSS_IMPORT = /@import\s{1,16}(["'])([^"'\s]{1,2048})\1/gi;

function splitTokens(value: string): string[] {
  return value
    .toLowerCase()
    .split(/[\t\n\f\r ]+/)
    .filter((t) => t.length > 0);
}

/**
 * Candidate URLs from a `srcset` value ("a.jpg 1x, b.jpg 2x"), following the
 * HTML "parse a srcset attribute" algorithm: a URL runs to the next
 * whitespace (trailing commas end the candidate), and descriptors run to the
 * next comma outside parentheses. So "img.jpg?w=1,2 100w" keeps its comma.
 */
export function parseSrcset(srcset: string): string[] {
  const urls: string[] = [];
  const isSpace = (c: string): boolean => /[\t\n\f\r ]/.test(c);
  let pos = 0;
  while (pos < srcset.length) {
    while (pos < srcset.length && (isSpace(srcset.charAt(pos)) || srcset.charAt(pos) === ","))
      pos++;
    if (pos >= srcset.length) break;
    const start = pos;
    while (pos < srcset.length && !isSpace(srcset.charAt(pos))) pos++;
    let url = srcset.slice(start, pos);
    if (url.endsWith(",")) {
      url = url.replace(/,+$/, "");
    } else {
      let depth = 0;
      while (pos < srcset.length) {
        const c = srcset.charAt(pos);
        if (c === "(") depth++;
        else if (c === ")" && depth > 0) depth--;
        else if (c === "," && depth === 0) break;
        pos++;
      }
    }
    if (url.length > 0) urls.push(url);
  }
  return urls;
}

/** URLs referenced from CSS text (a `<style>` block or a `style` attribute). */
export function cssUrls(css: string): string[] {
  const urls: string[] = [];
  for (const pattern of [CSS_URL, CSS_IMPORT]) {
    for (const match of css.matchAll(pattern)) {
      if (match[2] !== undefined) urls.push(match[2]);
    }
  }
  return urls;
}

function attr(attribs: Attributes, name: string): string | undefined {
  // A Map lookup avoids prototype keys like "constructor" on attacker-controlled markup.
  const value = new Map(Object.entries(attribs)).get(name);
  if (value === undefined) return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/** Every URL-bearing attribute of one start tag, classified. */
function referencesForTag(tag: string, attribs: Attributes): ResourceRef[] {
  const refs: ResourceRef[] = [];
  const add = (attribute: string, value: string | undefined, kind: ResourceKind): void => {
    if (value !== undefined) refs.push({ tag, attribute, value, kind });
  };

  if (UPGRADEABLE_TAGS.has(tag)) add("src", attr(attribs, "src"), "upgradeable");
  if (tag === "img") {
    for (const url of parseSrcset(attr(attribs, "srcset") ?? "")) add("srcset", url, "upgradeable");
  }
  if (tag === "video") add("poster", attr(attribs, "poster"), "upgradeable");
  if (tag === "source") {
    // <source> inside <picture>/<audio>/<video> feeds an upgradeable element.
    add("src", attr(attribs, "src"), "upgradeable");
    for (const url of parseSrcset(attr(attribs, "srcset") ?? "")) add("srcset", url, "upgradeable");
  }
  if (tag === "input" && attr(attribs, "type")?.toLowerCase() === "image") {
    add("src", attr(attribs, "src"), "blockable");
  }
  if (tag === "link") {
    const rels = splitTokens(attribs.rel ?? "");
    if (rels.some((rel) => FETCHING_LINK_RELS.has(rel))) {
      add("href", attr(attribs, "href"), "blockable");
    }
  }
  for (const name of BLOCKABLE_URL_ATTRIBUTES.get(tag) ?? []) {
    add(name, attr(attribs, name), "blockable");
  }
  for (const name of FORM_URL_ATTRIBUTES.get(tag) ?? []) {
    add(name, attr(attribs, name), "form");
  }
  for (const url of cssUrls(attribs.style ?? "")) add("style", url, "blockable");
  return refs;
}

/** Tokenizes `html` and returns every loadable reference, in document order. */
export function extractResources(html: string): ExtractedHtml {
  const references: ResourceRef[] = [];
  const metaCsp: string[] = [];
  let baseHref: string | undefined;
  let styleText: string | undefined;

  const parser = new Parser(
    {
      onopentag(name, attribs) {
        references.push(...referencesForTag(name, attribs));
        if (name === "base" && baseHref === undefined) baseHref = attr(attribs, "href");
        if (
          name === "meta" &&
          attribs["http-equiv"]?.trim().toLowerCase() === "content-security-policy"
        ) {
          const content = attr(attribs, "content");
          if (content !== undefined) metaCsp.push(content);
        }
        if (name === "style") styleText = "";
      },
      ontext(text) {
        if (styleText !== undefined) styleText += text;
      },
      onclosetag(name) {
        if (name === "style" && styleText !== undefined) {
          for (const url of cssUrls(styleText)) {
            references.push({ tag: "style", attribute: "css", value: url, kind: "blockable" });
          }
          styleText = undefined;
        }
      },
    },
    { decodeEntities: true, lowerCaseTags: true, lowerCaseAttributeNames: true },
  );
  parser.write(html);
  parser.end();
  return Object.freeze({
    references: Object.freeze(references),
    baseHref,
    metaCsp: Object.freeze(metaCsp),
  });
}
