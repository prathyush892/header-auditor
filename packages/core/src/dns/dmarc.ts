/**
 * DMARC (RFC 7489): tells receivers what to do with mail that fails SPF/DKIM
 * alignment for this domain, and where to send reports. SPF alone doesn't
 * protect the visible From: address; DMARC with p=reject does.
 */
import { makeFinding, Status, type Finding } from "../finding.js";
import type { DnsResolver } from "./resolver.js";

export const DMARC_CHECK = "DMARC";
export const DMARC_WEIGHT = 20;

export type DmarcPolicy = "none" | "quarantine" | "reject";
const POLICIES: ReadonlySet<string> = new Set(["none", "quarantine", "reject"]);

export interface DmarcRecord {
  readonly raw: string;
  readonly policy: DmarcPolicy;
  /** Policy for subdomains (`sp`); undefined means it falls back to `policy`. */
  readonly subdomainPolicy: DmarcPolicy | undefined;
  /** Percentage of failing mail the policy applies to (0-100, default 100). */
  readonly pct: number;
  /** Aggregate report destinations (`rua`). */
  readonly rua: readonly string[];
}

export type DmarcParseResult =
  | { readonly ok: true; readonly record: DmarcRecord }
  | { readonly ok: false; readonly error: string };

/** True for TXT strings that claim to be DMARC records (`v=DMARC1` as the first tag). */
export function isDmarcRecord(txt: string): boolean {
  return /^v\s*=\s*DMARC1\s*(?:;|$)/i.test(txt);
}

function parseTags(raw: string): Map<string, string> | string {
  const tags = new Map<string, string>();
  for (const part of raw.split(";")) {
    const trimmed = part.trim();
    if (trimmed === "") continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) return `malformed tag "${trimmed.slice(0, 40)}"`;
    const key = trimmed.slice(0, eq).trim().toLowerCase();
    if (tags.has(key)) return `duplicate tag "${key}"`;
    tags.set(key, trimmed.slice(eq + 1).trim());
  }
  return tags;
}

function parsePolicy(value: string | undefined): DmarcPolicy | undefined {
  const v = value?.toLowerCase();
  return v !== undefined && POLICIES.has(v) ? (v as DmarcPolicy) : undefined;
}

/** Parses one DMARC record. Errors mean receivers would discard it. */
export function parseDmarc(raw: string): DmarcParseResult {
  if (!isDmarcRecord(raw)) return { ok: false, error: "record does not start with v=DMARC1" };
  const tags = parseTags(raw);
  if (typeof tags === "string") return { ok: false, error: tags };
  const policy = parsePolicy(tags.get("p"));
  if (policy === undefined) {
    return {
      ok: false,
      error: tags.has("p") ? `invalid p="${tags.get("p") ?? ""}"` : "missing p tag",
    };
  }
  const spRaw = tags.get("sp");
  const subdomainPolicy = parsePolicy(spRaw);
  if (spRaw !== undefined && subdomainPolicy === undefined) {
    return { ok: false, error: `invalid sp="${spRaw}"` };
  }
  const pctRaw = tags.get("pct") ?? "100";
  const pct = /^\d{1,3}$/.test(pctRaw) ? Number(pctRaw) : NaN;
  if (!(pct >= 0 && pct <= 100)) return { ok: false, error: `invalid pct="${pctRaw}"` };
  const rua = (tags.get("rua") ?? "")
    .split(",")
    .map((u) => u.trim())
    .filter((u) => u !== "");
  return { ok: true, record: { raw, policy, subdomainPolicy, pct, rua } };
}

// ---------------------------------------------------------------- lookups

export interface DmarcObservation {
  readonly domain: string;
  /** Name the record was found at: `_dmarc.<domain>` or `_dmarc.<organizational domain>`. */
  readonly foundAt: string | undefined;
  /** Every DMARC record at `foundAt`. */
  readonly records: readonly string[];
  readonly record: DmarcRecord | undefined;
  readonly error: string | undefined;
  /** True when the record is inherited from the organizational domain, so `sp` applies. */
  readonly inherited: boolean;
}

/**
 * Naive organizational domain: the last two labels. Correct for `example.com`,
 * wrong for multi-label suffixes like `example.co.uk`; pass the real one
 * (from the Public Suffix List) through `organizationalDomain` when known.
 */
export function naiveOrganizationalDomain(domain: string): string {
  return domain.split(".").slice(-2).join(".");
}

async function recordsAt(name: string, resolver: DnsResolver): Promise<string[]> {
  return (await resolver.txt(name)).filter(isDmarcRecord);
}

/**
 * RFC 7489 §6.6.3 discovery: `_dmarc.<domain>`, then `_dmarc.<organizational
 * domain>` if the first has none. Throws DnsLookupError if a lookup fails.
 */
export async function lookupDmarc(
  domain: string,
  resolver: DnsResolver,
  organizationalDomain: string = naiveOrganizationalDomain(domain),
): Promise<DmarcObservation> {
  let foundAt = `_dmarc.${domain}`;
  let records = await recordsAt(foundAt, resolver);
  let inherited = false;
  if (records.length === 0 && organizationalDomain !== domain) {
    foundAt = `_dmarc.${organizationalDomain}`;
    records = await recordsAt(foundAt, resolver);
    inherited = true;
  }
  if (records.length === 0) {
    return {
      domain,
      foundAt: undefined,
      records,
      record: undefined,
      error: undefined,
      inherited: false,
    };
  }
  if (records.length > 1) {
    const error = `${String(records.length)} DMARC records at ${foundAt}`;
    return { domain, foundAt, records, record: undefined, error, inherited };
  }
  const parsed = parseDmarc(records[0] ?? "");
  return parsed.ok
    ? { domain, foundAt, records, record: parsed.record, error: undefined, inherited }
    : { domain, foundAt, records, record: undefined, error: parsed.error, inherited };
}

// ---------------------------------------------------------------- grading

/** Enforcement applied to only part of the mail (pct < 100) earns at most this. */
const PARTIAL_ENFORCEMENT_SCORE = 10;

function scoreFor(policy: DmarcPolicy, pct: number): number {
  switch (policy) {
    case "none":
      return 5;
    case "quarantine":
      return pct < 100 ? PARTIAL_ENFORCEMENT_SCORE : 15;
    case "reject":
      return pct < 100 ? PARTIAL_ENFORCEMENT_SCORE : DMARC_WEIGHT;
  }
}

export function checkDmarc(obs: DmarcObservation): Finding {
  const base = { check: DMARC_CHECK, weight: DMARC_WEIGHT };
  if (obs.foundAt === undefined) {
    return makeFinding({
      ...base,
      status: Status.Fail,
      detail: `No DMARC record at _dmarc.${obs.domain}: nothing tells receivers to reject mail spoofing this domain.`,
      recommendation: `Start monitoring with \`_dmarc.${obs.domain}. TXT "v=DMARC1; p=none; rua=mailto:dmarc@${obs.domain}"\`, then move to p=quarantine and p=reject.`,
    });
  }
  if (obs.record === undefined) {
    return makeFinding({
      ...base,
      status: Status.Fail,
      detail: `DMARC at ${obs.foundAt} is invalid (${obs.error ?? "unparseable"}), so receivers ignore it.`,
      recommendation:
        'Publish exactly one record of the form "v=DMARC1; p=reject; rua=mailto:...".',
    });
  }
  const r = obs.record;
  // A subdomain that inherits the organizational record gets sp (falling back to p).
  const effective = obs.inherited ? (r.subdomainPolicy ?? r.policy) : r.policy;
  let score = scoreFor(effective, r.pct);
  const notes: string[] = [];
  const fixes: string[] = [];
  if (obs.inherited) notes.push(`inherited from ${obs.foundAt}`);
  if (r.pct < 100 && effective !== "none") {
    notes.push(`applied to ${String(r.pct)}% of failing mail`);
    fixes.push("Raise pct to 100 (or remove it).");
  }
  if (!obs.inherited && r.policy !== "none" && r.subdomainPolicy === "none") {
    score = Math.min(score, PARTIAL_ENFORCEMENT_SCORE);
    notes.push("but sp=none leaves subdomains spoofable");
    fixes.push("Set sp=quarantine or sp=reject (or remove sp to inherit p).");
  }
  if (effective === "none")
    fixes.unshift("p=none only monitors; move to p=quarantine, then p=reject.");
  if (effective === "quarantine")
    fixes.push("Move to p=reject once reports show legitimate mail passes.");
  if (r.rua.length === 0) fixes.push("Add rua=mailto:... to receive aggregate reports.");
  const status = score === DMARC_WEIGHT ? Status.Pass : Status.Warn;
  const suffix = notes.length > 0 ? ` (${notes.join("; ")})` : "";
  return makeFinding({
    ...base,
    status,
    score,
    detail: `DMARC policy ${effective}${suffix}: ${r.raw}`,
    recommendation: fixes.join(" "),
  });
}
