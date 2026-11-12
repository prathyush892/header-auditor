/**
 * Content-Security-Policy parser.
 *
 * Follows the "parse a serialized CSP" algorithm from CSP Level 3 (§2.2.1):
 *
 * 1. Split the policy on ";".
 * 2. Strip ASCII whitespace; skip empty directives.
 * 3. The directive name is everything up to the first ASCII whitespace,
 *    lowercased. Names that aren't valid directive names are ignored.
 * 4. If the policy already has that directive, the duplicate is ignored
 *    (first one wins, which is also what browsers do).
 * 5. The value is the rest, split on ASCII whitespace into source tokens.
 *
 * Source keywords such as 'self' and 'unsafe-inline' are case-insensitive, so
 * every helper here compares lowercased tokens; the tokens themselves are kept
 * as sent so reports show exactly what the server returned.
 *
 * Note: one header value is parsed as one policy. Comma-separated policies in
 * a single value and multiple CSP headers are not merged yet (see ROADMAP).
 */

/** Directive name → its source tokens (possibly empty). Insertion-ordered. */
export type CspPolicy = ReadonlyMap<string, readonly string[]>;

/** ASCII whitespace as defined by the Infra standard: TAB, LF, FF, CR, SPACE. */
const ASCII_WHITESPACE = /[\t\n\f\r ]+/;
/** CSP3 `directive-name = 1*( ALPHA / DIGIT / "-" )`, after lowercasing. */
const DIRECTIVE_NAME = /^[a-z0-9-]+$/;

/** Hash algorithms CSP3 allows in hash-source expressions. */
const HASH_PREFIXES = ["'sha256-", "'sha384-", "'sha512-"] as const;

/**
 * Source expressions that let *any* origin match: the `*` wildcard, a bare
 * scheme (`https:` matches every HTTPS host) or a wildcard host (`https://*`).
 */
const ANY_ORIGIN_SOURCE = /^(?:\*|https?:|https?:\/\/\*)$/;

function splitTokens(text: string): string[] {
  return text.split(ASCII_WHITESPACE).filter((t) => t.length > 0);
}

export function parseCsp(serialized: string): CspPolicy {
  const policy = new Map<string, readonly string[]>();
  for (const rawDirective of serialized.split(";")) {
    const [rawName, ...sources] = splitTokens(rawDirective);
    if (rawName === undefined) continue;
    const name = rawName.toLowerCase();
    if (!DIRECTIVE_NAME.test(name) || policy.has(name)) continue;
    policy.set(name, Object.freeze(sources));
  }
  return policy;
}

/** True if `sources` contains `keyword` (e.g. "'unsafe-inline'"), ignoring case. */
export function hasSource(sources: readonly string[], keyword: string): boolean {
  const wanted = keyword.toLowerCase();
  return sources.some((s) => s.toLowerCase() === wanted);
}

/** True if any source starts with `prefix` (e.g. "'nonce-"), ignoring case. */
export function hasSourcePrefix(sources: readonly string[], prefix: string): boolean {
  const wanted = prefix.toLowerCase();
  return sources.some((s) => s.toLowerCase().startsWith(wanted));
}

/** The first source that matches every origin (`*`, `https:`, ...), if any. */
export function findAnyOriginSource(sources: readonly string[]): string | undefined {
  return sources.find((s) => ANY_ORIGIN_SOURCE.test(s.toLowerCase()));
}

/**
 * Sources that apply to classic `<script>` loading: `script-src`, falling back
 * to `default-src`. Undefined when neither directive is present.
 */
export function effectiveScriptSources(policy: CspPolicy): readonly string[] | undefined {
  return policy.get("script-src") ?? policy.get("default-src");
}

/**
 * Per CSP2+, browsers ignore 'unsafe-inline' when a nonce, a hash or
 * 'strict-dynamic' is also present, so a fallback for old browsers is safe.
 */
export function neutralizesUnsafeInline(sources: readonly string[]): boolean {
  return (
    hasSourcePrefix(sources, "'nonce-") ||
    HASH_PREFIXES.some((p) => hasSourcePrefix(sources, p)) ||
    hasSource(sources, "'strict-dynamic'")
  );
}
