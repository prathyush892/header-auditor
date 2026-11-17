/**
 * SPF (RFC 7208): which servers may send mail as this domain. Missing or
 * permissive SPF makes it easy to spoof the domain in phishing mail.
 *
 * `parseSpf()` is pure. `lookupSpf()` fetches the record and walks its
 * `include:` / `redirect=` chain to count DNS lookups (RFC 7208 §4.6.4 caps
 * evaluation at 10; one more and receivers return permerror, i.e. SPF is
 * silently ignored). `checkSpf()` grades the observation.
 */
import { isIPv4, isIPv6 } from "node:net";
import { makeFinding, Status, type Finding } from "../finding.js";
import { isDnsLookupError, type DnsResolver } from "./resolver.js";

export const SPF_CHECK = "SPF";
export const SPF_WEIGHT = 15;
/** RFC 7208 §4.6.4: at most 10 mechanisms/modifiers that need DNS lookups. */
export const SPF_LOOKUP_LIMIT = 10;

export type SpfQualifier = "+" | "-" | "~" | "?";
export type SpfMechanismName = "all" | "include" | "a" | "mx" | "ptr" | "ip4" | "ip6" | "exists";

export interface SpfMechanism {
  readonly qualifier: SpfQualifier;
  readonly name: SpfMechanismName;
  /** Text after `:` (domain or address), without the CIDR suffix; "" when absent. */
  readonly target: string;
}

export interface SpfRecord {
  readonly raw: string;
  readonly mechanisms: readonly SpfMechanism[];
  readonly redirect: string | undefined;
}

export type SpfParseResult =
  | { readonly ok: true; readonly record: SpfRecord }
  | { readonly ok: false; readonly error: string };

const LOOKUP_MECHANISMS: ReadonlySet<SpfMechanismName> = new Set([
  "include",
  "a",
  "mx",
  "ptr",
  "exists",
]);
const MODIFIER = /^([a-z][a-z0-9_.-]{0,63})=(.*)$/i;

const MECHANISM_NAMES: ReadonlySet<string> = new Set([
  "all",
  "include",
  "a",
  "mx",
  "ptr",
  "ip4",
  "ip6",
  "exists",
]);

interface MechanismParts {
  qualifier: SpfQualifier;
  name: SpfMechanismName;
  target: string;
  prefix: string | undefined;
  prefix6: string | undefined;
}

/** Splits `~ip4:192.0.2.0/24` or `a:host//64`; undefined when it isn't a mechanism. */
function splitMechanism(term: string): MechanismParts | undefined {
  const first = term.charAt(0);
  const hasQualifier = first === "+" || first === "-" || first === "~" || first === "?";
  const rest = hasQualifier ? term.slice(1) : term;
  const end = rest.search(/[:/]/);
  const name = (end === -1 ? rest : rest.slice(0, end)).toLowerCase();
  if (!MECHANISM_NAMES.has(name)) return undefined;
  let tail = end === -1 ? "" : rest.slice(end);
  let target = "";
  if (tail.startsWith(":")) {
    const slash = tail.indexOf("/");
    target = slash === -1 ? tail.slice(1) : tail.slice(1, slash);
    tail = slash === -1 ? "" : tail.slice(slash);
  }
  const prefixes = splitPrefixes(tail);
  if (!prefixes) return undefined;
  return {
    qualifier: hasQualifier ? first : "+",
    name: name as SpfMechanismName,
    target,
    ...prefixes,
  };
}

const PREFIX = /^\d{1,3}$/;

/** `"/24//64"` → `{ prefix: "24", prefix6: "64" }`; undefined when malformed. */
function splitPrefixes(
  tail: string,
): { prefix: string | undefined; prefix6: string | undefined } | undefined {
  if (tail === "") return { prefix: undefined, prefix6: undefined };
  if (tail.startsWith("//")) {
    const prefix6 = tail.slice(2);
    return PREFIX.test(prefix6) ? { prefix: undefined, prefix6 } : undefined;
  }
  if (!tail.startsWith("/")) return undefined;
  const dual = tail.indexOf("//");
  const prefix = dual === -1 ? tail.slice(1) : tail.slice(1, dual);
  const prefix6 = dual === -1 ? undefined : tail.slice(dual + 2);
  if (!PREFIX.test(prefix) || (prefix6 !== undefined && !PREFIX.test(prefix6))) return undefined;
  return { prefix, prefix6 };
}

/** True for TXT strings that are SPF records (`v=spf1` then a space or the end). */
export function isSpfRecord(txt: string): boolean {
  return /^v=spf1(?: |$)/i.test(txt);
}

/** `prefix` is the first `/n` (IPv4 for a/mx, the only prefix for ip4/ip6); `prefix6` the `//n`. */
function validateMechanism(m: SpfMechanism, prefix?: string, prefix6?: string): string | undefined {
  const needsTarget =
    m.name === "include" || m.name === "exists" || m.name === "ip4" || m.name === "ip6";
  if (needsTarget && m.target === "") return `"${m.name}" needs a value`;
  if (m.name === "all" && (m.target !== "" || prefix !== undefined || prefix6 !== undefined)) {
    return '"all" takes no value';
  }
  const prefixAllowed = m.name === "a" || m.name === "mx" || m.name === "ip4" || m.name === "ip6";
  if (!prefixAllowed && m.name !== "all" && (prefix !== undefined || prefix6 !== undefined)) {
    return `"${m.name}" takes no prefix length`;
  }
  if ((m.name === "ip4" || m.name === "ip6") && prefix6 !== undefined) {
    return `invalid prefix length on "${m.name}"`;
  }
  if (m.name === "ip4" && (!isIPv4(m.target) || Number(prefix ?? 32) > 32)) {
    return `invalid ip4 "${m.target}"`;
  }
  if (m.name === "ip6" && (!isIPv6(m.target) || Number(prefix ?? 128) > 128)) {
    return `invalid ip6 "${m.target}"`;
  }
  if (
    (m.name === "a" || m.name === "mx") &&
    (Number(prefix ?? 32) > 32 || Number(prefix6 ?? 128) > 128)
  ) {
    return `invalid prefix length on "${m.name}"`;
  }
  return undefined;
}

/** Parses one SPF record. Errors are what a receiver would report as permerror. */
export function parseSpf(raw: string): SpfParseResult {
  if (!isSpfRecord(raw)) return { ok: false, error: "record does not start with v=spf1" };
  const terms = raw
    .split(" ")
    .filter((t) => t !== "")
    .slice(1);
  const mechanisms: SpfMechanism[] = [];
  const modifiers = new Map<string, string>();
  for (const term of terms) {
    const parts = splitMechanism(term);
    if (parts) {
      const m: SpfMechanism = {
        qualifier: parts.qualifier,
        name: parts.name,
        target: parts.target,
      };
      const error = validateMechanism(m, parts.prefix, parts.prefix6);
      if (error) return { ok: false, error };
      mechanisms.push(m);
      continue;
    }
    const mod = MODIFIER.exec(term);
    if (mod) {
      const key = (mod[1] ?? "").toLowerCase();
      if ((key === "redirect" || key === "exp") && modifiers.has(key)) {
        return { ok: false, error: `"${key}" appears more than once` };
      }
      modifiers.set(key, mod[2] ?? "");
      continue;
    }
    return { ok: false, error: `unknown term "${term.slice(0, 60)}"` };
  }
  const redirect = modifiers.get("redirect");
  if (redirect === "") return { ok: false, error: '"redirect" needs a domain' };
  return { ok: true, record: { raw, mechanisms, redirect } };
}

// ---------------------------------------------------------------- lookups

export interface SpfObservation {
  readonly domain: string;
  /** Every SPF record published at the domain (more than one is itself an error). */
  readonly records: readonly string[];
  readonly record: SpfRecord | undefined;
  /** Why receivers would return permerror, if they would. */
  readonly permerror: string | undefined;
  /** Qualifier of the `all` that ends evaluation (following `redirect=`); undefined = none. */
  readonly all: SpfQualifier | undefined;
  /** DNS-querying terms counted across the include/redirect tree. */
  readonly lookups: number;
  /** False when part of the tree couldn't be followed (lookup failure or macros). */
  readonly complete: boolean;
  readonly usesPtr: boolean;
}

interface WalkState {
  lookups: number;
  complete: boolean;
  usesPtr: boolean;
  permerror: string | undefined;
  readonly visited: Set<string>;
}

type FetchResult = { record: SpfRecord } | { permerror: string } | { failed: true };

async function fetchSpf(name: string, resolver: DnsResolver): Promise<FetchResult> {
  let txt: readonly string[];
  try {
    txt = await resolver.txt(name);
  } catch (err) {
    if (isDnsLookupError(err)) return { failed: true };
    throw err;
  }
  const spf = txt.filter(isSpfRecord);
  if (spf.length === 0) return { permerror: `${name} has no SPF record` };
  if (spf.length > 1) return { permerror: `${name} has ${String(spf.length)} SPF records` };
  const parsed = parseSpf(spf[0] ?? "");
  return parsed.ok ? { record: parsed.record } : { permerror: `${name}: ${parsed.error}` };
}

/** Follows include/redirect targets, counting lookups. Returns the effective `all`. */
async function walk(
  record: SpfRecord,
  resolver: DnsResolver,
  state: WalkState,
): Promise<SpfQualifier | undefined> {
  for (const m of record.mechanisms) {
    if (state.permerror !== undefined || state.lookups > SPF_LOOKUP_LIMIT) return undefined;
    if (m.name === "ptr") state.usesPtr = true;
    if (!LOOKUP_MECHANISMS.has(m.name)) continue;
    state.lookups++;
    if (m.name === "include") await follow(m.target, resolver, state);
  }
  const all = record.mechanisms.find((m) => m.name === "all");
  if (all) return all.qualifier; // RFC 7208 §6.1: redirect is ignored when "all" is present
  if (record.redirect === undefined || state.permerror !== undefined) return undefined;
  state.lookups++;
  return follow(record.redirect, resolver, state);
}

async function follow(
  target: string,
  resolver: DnsResolver,
  state: WalkState,
): Promise<SpfQualifier | undefined> {
  if (state.lookups > SPF_LOOKUP_LIMIT) return undefined;
  if (target.includes("%")) {
    state.complete = false; // macros expand per message; can't be followed statically
    return undefined;
  }
  const name = target.toLowerCase().replace(/\.$/, "");
  if (state.visited.has(name)) {
    state.permerror = `include/redirect loop through ${name}`;
    return undefined;
  }
  state.visited.add(name);
  const fetched = await fetchSpf(name, resolver);
  if ("failed" in fetched) {
    state.complete = false;
    return undefined;
  }
  if ("permerror" in fetched) {
    state.permerror = fetched.permerror;
    return undefined;
  }
  return walk(fetched.record, resolver, state);
}

/** Fetches and evaluates the domain's SPF. Throws DnsLookupError if the first lookup fails. */
export async function lookupSpf(domain: string, resolver: DnsResolver): Promise<SpfObservation> {
  const records = (await resolver.txt(domain)).filter(isSpfRecord);
  const empty = { domain, records, all: undefined, lookups: 0, complete: true, usesPtr: false };
  if (records.length !== 1) {
    const permerror =
      records.length > 1 ? `${String(records.length)} SPF records published` : undefined;
    return { ...empty, record: undefined, permerror };
  }
  const parsed = parseSpf(records[0] ?? "");
  if (!parsed.ok) return { ...empty, record: undefined, permerror: parsed.error };
  const state: WalkState = {
    lookups: 0,
    complete: true,
    usesPtr: false,
    permerror: undefined,
    visited: new Set([domain]),
  };
  const all = await walk(parsed.record, resolver, state);
  return {
    domain,
    records,
    record: parsed.record,
    permerror:
      state.permerror ??
      (state.lookups > SPF_LOOKUP_LIMIT
        ? `more than ${String(SPF_LOOKUP_LIMIT)} DNS lookups`
        : undefined),
    all,
    lookups: state.lookups,
    complete: state.complete,
    usesPtr: state.usesPtr,
  };
}

// ---------------------------------------------------------------- grading

const ALL_SCORES: Readonly<Record<SpfQualifier, number>> = { "-": 15, "~": 10, "?": 5, "+": 0 };

export function checkSpf(obs: SpfObservation): Finding {
  const base = { check: SPF_CHECK, weight: SPF_WEIGHT };
  if (obs.records.length === 0) {
    return makeFinding({
      ...base,
      status: Status.Fail,
      detail: `No SPF record on ${obs.domain}: receivers can't tell forged mail from real mail.`,
      recommendation: `Publish a TXT record listing your mail senders, e.g. \`v=spf1 include:_spf.your-provider.example -all\`. If ${obs.domain} sends no mail, publish \`v=spf1 -all\`.`,
    });
  }
  if (obs.permerror !== undefined) {
    return makeFinding({
      ...base,
      status: Status.Fail,
      detail: `SPF is broken (${obs.permerror}); receivers return permerror and ignore it.`,
      recommendation:
        "Publish exactly one valid v=spf1 record and keep it under 10 DNS lookups (flatten includes or drop unused ones).",
    });
  }
  const notes: string[] = [`${String(obs.lookups)}/${String(SPF_LOOKUP_LIMIT)} DNS lookups`];
  if (!obs.complete) notes.push("some includes could not be followed");
  const summary = `${obs.records[0] ?? ""} (${notes.join("; ")})`;
  const ptrNote = obs.usesPtr ? ' Remove "ptr": it is slow and deprecated (RFC 7208 §5.5).' : "";
  const q = obs.all;
  if (q === "+") {
    return makeFinding({
      ...base,
      status: Status.Fail,
      detail: `SPF ends in +all, which authorises every server on the internet: ${summary}.`,
      recommendation: `Replace +all with -all.${ptrNote}`,
    });
  }
  if (q === "-") {
    return makeFinding({
      ...base,
      status: obs.usesPtr ? Status.Warn : Status.Pass,
      score: obs.usesPtr ? ALL_SCORES["~"] : SPF_WEIGHT,
      detail: `SPF hard-fails unlisted senders: ${summary}.`,
      recommendation: ptrNote.trim(),
    });
  }
  const what =
    q === "~"
      ? "soft-fails (~all) unlisted senders, so receivers usually accept them into spam"
      : "has no enforcing all mechanism (neutral), so unlisted senders aren't rejected";
  return makeFinding({
    ...base,
    status: Status.Warn,
    score: ALL_SCORES[q ?? "?"],
    detail: `SPF ${what}: ${summary}.`,
    recommendation: `End the record with -all once every legitimate sender is listed (DMARC reports show which ones are).${ptrNote}`,
  });
}
