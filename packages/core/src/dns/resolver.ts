/**
 * The DNS side of the scanner: a small resolver interface, a production
 * implementation on top of `node:dns`, and domain-name validation.
 *
 * The checks in this folder never call `node:dns` directly. They receive a
 * `DnsResolver`, so unit tests pass an in-memory fixture and integration tests
 * point the real resolver at a local DNS server on 127.0.0.1.
 */
import { promises as dns } from "node:dns";
import { isIP } from "node:net";
import { domainToASCII } from "node:url";

/** One CAA resource record (RFC 8659). Tags are lower-cased. */
export interface CaaRecord {
  /** Issuer-critical flag (bit 128): a CA that doesn't understand the tag must refuse to issue. */
  readonly critical: boolean;
  readonly tag: string;
  readonly value: string;
}

/**
 * The lookups the DNS checks need. Both methods resolve to `[]` when the name
 * has no records of that type (NODATA) or doesn't exist (NXDOMAIN): for these
 * checks "no record" is an answer, not an error. Anything else (timeout,
 * SERVFAIL, refused) rejects with a `DnsLookupError`.
 */
export interface DnsResolver {
  /** TXT records at `name`, each record's character-strings joined (RFC 7208 §3.3). */
  txt(name: string): Promise<readonly string[]>;
  caa(name: string): Promise<readonly CaaRecord[]>;
}

export type DnsErrorCode = "TIMEOUT" | "SERVFAIL" | "REFUSED" | "UNREACHABLE" | "BAD_RESPONSE";

/** A lookup that failed for a reason other than "the record doesn't exist". */
export class DnsLookupError extends Error {
  override readonly name = "DnsLookupError";

  constructor(
    readonly qname: string,
    readonly rrtype: "TXT" | "CAA",
    readonly code: DnsErrorCode,
    options?: ErrorOptions,
  ) {
    super(`${rrtype} lookup for ${qname} failed: ${code}`, options);
  }
}

export function isDnsLookupError(err: unknown): err is DnsLookupError {
  return err instanceof DnsLookupError;
}

// ------------------------------------------------------------- validation

export const MAX_DOMAIN_LENGTH = 253;

/** One DNS label: 1-63 of [a-z0-9_-], not starting or ending with a hyphen. */
export function isDnsLabel(label: string): boolean {
  return (
    label.length >= 1 &&
    label.length <= 63 &&
    /^[a-z0-9_-]+$/i.test(label) &&
    !label.startsWith("-") &&
    !label.endsWith("-")
  );
}

/**
 * Validates and normalises a domain for DNS queries: trims, drops a trailing
 * dot, lower-cases and converts IDNs to punycode. Throws RangeError for IP
 * literals, single-label names and anything that isn't a valid hostname.
 */
export function normalizeDomain(input: string): string {
  if (typeof input !== "string") throw new TypeError("domain must be a string");
  let name = input.trim();
  if (name.endsWith(".")) name = name.slice(0, -1);
  if (name === "") throw new RangeError("domain must not be empty");
  if (isIP(name.replace(/^\[|\]$/g, "")) !== 0) {
    throw new RangeError("DNS checks need a domain name, not an IP address");
  }
  const ascii = domainToASCII(name);
  if (ascii === "" || ascii.length > MAX_DOMAIN_LENGTH) {
    throw new RangeError(`Invalid domain name: ${JSON.stringify(input.slice(0, 80))}`);
  }
  const labels = ascii.split(".");
  if (labels.length < 2) {
    throw new RangeError("DNS checks need a fully qualified domain name (e.g. example.com)");
  }
  if (!labels.every(isDnsLabel)) {
    throw new RangeError(`Invalid domain name: ${JSON.stringify(input.slice(0, 80))}`);
  }
  if (/^[0-9]+$/.test(labels.at(-1) ?? "")) {
    throw new RangeError("DNS checks need a domain name, not an IP address");
  }
  return ascii;
}

/** The domain to run DNS checks against for a scanned URL (its hostname). */
export function dnsTargetFromUrl(url: string | URL): string {
  const parsed = typeof url === "string" ? new URL(url) : url;
  return normalizeDomain(parsed.hostname);
}

/** `example.com` for `a.b.example.com`: every ancestor, nearest first, excluding the TLD. */
export function parentDomains(domain: string): string[] {
  const labels = domain.split(".");
  const parents: string[] = [];
  for (let i = 1; i < labels.length - 1; i++) parents.push(labels.slice(i).join("."));
  return parents;
}

// -------------------------------------------------------- system resolver

export const DEFAULT_DNS_TIMEOUT_MS = 3000;
export const MAX_DNS_TIMEOUT_MS = 30_000;
export const DEFAULT_DNS_TRIES = 2;

export interface DnsResolverOptions {
  /** Per-attempt timeout in ms (1-30000). Default 3000. */
  timeoutMs?: number;
  /** Attempts per server (1-5). Default 2. */
  tries?: number;
  /** Nameservers to use instead of the system ones, e.g. `["127.0.0.1:5353"]`. */
  servers?: readonly string[];
}

const EMPTY_CODES = new Set<string>([dns.NODATA, dns.NOTFOUND]);
const ERROR_CODES = new Map<string, DnsErrorCode>([
  [dns.TIMEOUT, "TIMEOUT"],
  [dns.SERVFAIL, "SERVFAIL"],
  [dns.REFUSED, "REFUSED"],
  [dns.CONNREFUSED, "UNREACHABLE"],
]);

function errorCode(err: unknown): string | undefined {
  if (typeof err === "object" && err !== null && "code" in err) {
    return typeof err.code === "string" ? err.code : undefined;
  }
  return undefined;
}

/** Turns a node:dns rejection into `[]` (no such record) or a DnsLookupError. */
async function settle<T>(
  qname: string,
  rrtype: "TXT" | "CAA",
  lookup: Promise<readonly T[]>,
): Promise<readonly T[]> {
  try {
    return await lookup;
  } catch (err) {
    const code = errorCode(err) ?? "";
    if (EMPTY_CODES.has(code)) return [];
    throw new DnsLookupError(qname, rrtype, ERROR_CODES.get(code) ?? "BAD_RESPONSE", {
      cause: err,
    });
  }
}

/** Node returns CAA as `{ critical: 0, issue: "ca.test" }`: one key named after the tag. */
export function caaFromNode(record: Readonly<Record<string, unknown>>): CaaRecord | undefined {
  const critical = typeof record.critical === "number" && (record.critical & 128) !== 0;
  for (const [key, value] of Object.entries(record)) {
    if (key === "critical" || typeof value !== "string") continue;
    return { critical, tag: key.toLowerCase(), value };
  }
  return undefined;
}

function validateInt(name: string, value: number, min: number, max: number): number {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new RangeError(`${name} must be an integer between ${String(min)} and ${String(max)}`);
  }
  return value;
}

/** A `DnsResolver` backed by c-ares (`node:dns`), with bounded timeouts. */
export function createDnsResolver(options: DnsResolverOptions = {}): DnsResolver {
  const timeout = validateInt(
    "timeoutMs",
    options.timeoutMs ?? DEFAULT_DNS_TIMEOUT_MS,
    1,
    MAX_DNS_TIMEOUT_MS,
  );
  const tries = validateInt("tries", options.tries ?? DEFAULT_DNS_TRIES, 1, 5);
  const resolver = new dns.Resolver({ timeout, tries });
  if (options.servers !== undefined) {
    if (options.servers.length === 0) throw new RangeError("servers must not be empty");
    resolver.setServers([...options.servers]);
  }
  return {
    txt: async (name) => {
      const records = await settle(name, "TXT", resolver.resolveTxt(name));
      return records.map((chunks) => chunks.join(""));
    },
    caa: async (name) => {
      const records = await settle(name, "CAA", resolver.resolveCaa(name));
      return records.flatMap((r) => {
        const caa = caaFromNode(r as unknown as Record<string, unknown>);
        return caa ? [caa] : [];
      });
    },
  };
}
