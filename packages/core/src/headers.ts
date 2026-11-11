/**
 * Case-insensitive, multi-value view of HTTP response headers — the TypeScript
 * port of the Python `Headers` class.
 *
 * Named `HeaderMap` rather than `Headers` so it never shadows the global
 * WHATWG `Headers` class that `fetch` returns. That class joins repeated
 * headers with ", ", which corrupts `Set-Cookie` (cookie dates contain commas),
 * so the scanner keeps every value separately instead.
 */

export type HeaderEntry = readonly [name: string, value: string];

/** Anything a HeaderMap can be built from. */
export type HeaderInput =
  | Iterable<HeaderEntry>
  | Readonly<Record<string, string | readonly string[] | undefined>>
  | globalThis.Headers;

/** RFC 9110 `token`: the only characters allowed in a field name. */
const FIELD_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
/** CR, LF and NUL are never valid inside a field value (header injection). */
const FORBIDDEN_VALUE_CHARS = /[\r\n\0]/;

function validateEntry(name: string, value: string): void {
  if (!FIELD_NAME.test(name)) {
    throw new TypeError(`Invalid header name: ${JSON.stringify(name)}`);
  }
  if (FORBIDDEN_VALUE_CHARS.test(value)) {
    throw new TypeError(`Invalid characters in value of header "${name}"`);
  }
}

function isWhatwgHeaders(input: HeaderInput): input is globalThis.Headers {
  return typeof globalThis.Headers === "function" && input instanceof globalThis.Headers;
}

function isIterable(input: HeaderInput): input is Iterable<HeaderEntry> {
  return typeof (input as Partial<Iterable<HeaderEntry>>)[Symbol.iterator] === "function";
}

function* entriesOf(input: HeaderInput): Generator<HeaderEntry> {
  if (isWhatwgHeaders(input)) {
    for (const [name, value] of input) {
      if (name !== "set-cookie") yield [name, value];
    }
    // getSetCookie() returns each Set-Cookie line unjoined.
    for (const cookie of input.getSetCookie()) yield ["set-cookie", cookie];
    return;
  }
  if (isIterable(input)) {
    yield* input;
    return;
  }
  for (const [name, value] of Object.entries(input)) {
    if (value === undefined) continue;
    if (typeof value === "string") {
      yield [name, value];
    } else {
      for (const v of value) yield [name, v];
    }
  }
}

export class HeaderMap {
  readonly #values = new Map<string, string[]>();

  /**
   * @throws TypeError if a header name is not an RFC 9110 token or a value
   *   contains CR, LF or NUL.
   */
  constructor(input: HeaderInput = []) {
    for (const [name, rawValue] of entriesOf(input)) {
      validateEntry(name, rawValue);
      const key = name.toLowerCase();
      const value = rawValue.trim();
      const existing = this.#values.get(key);
      if (existing) existing.push(value);
      else this.#values.set(key, [value]);
    }
  }

  /** First value of `name`, or undefined if absent (matches Python `get`). */
  get(name: string): string | undefined {
    return this.#values.get(name.toLowerCase())?.[0];
  }

  /** Every value of `name` in arrival order; empty when absent. */
  getAll(name: string): string[] {
    return [...(this.#values.get(name.toLowerCase()) ?? [])];
  }

  has(name: string): boolean {
    return this.#values.has(name.toLowerCase());
  }
}
