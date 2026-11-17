/**
 * CAA (RFC 8659): which certificate authorities may issue certificates for a
 * domain. Without it, any of the ~100 publicly trusted CAs can, so one CA with
 * weak domain validation is enough for an attacker to get a valid certificate.
 */
import { makeFinding, Status, type Finding } from "../finding.js";
import { isDnsLabel, parentDomains, type CaaRecord, type DnsResolver } from "./resolver.js";

export const CAA_CHECK = "CAA";
export const CAA_WEIGHT = 10;
const PARTIAL = 5;

/** Tags defined by RFC 8659 plus the RFC 8657 / CA/B Forum additions a CA understands. */
export const KNOWN_CAA_TAGS: ReadonlySet<string> = new Set([
  "issue",
  "issuewild",
  "iodef",
  "issuemail",
  "contactemail",
  "contactphone",
]);

/** The relevant CAA RRset and where it was found (the domain itself or an ancestor). */
export interface CaaObservation {
  readonly domain: string;
  readonly records: readonly CaaRecord[];
  /** Name the records came from; undefined when no CAA exists up the tree. */
  readonly foundAt: string | undefined;
}

/**
 * RFC 8659 §3 "tree climbing": a CA uses the CAA set of the closest name that
 * has one, so `api.example.com` inherits `example.com`'s policy.
 */
export async function lookupCaa(domain: string, resolver: DnsResolver): Promise<CaaObservation> {
  for (const name of [domain, ...parentDomains(domain)]) {
    const records = await resolver.caa(name);
    if (records.length > 0) return { domain, records, foundAt: name };
  }
  return { domain, records: [], foundAt: undefined };
}

/**
 * Parses an `issue`/`issuewild` value: `ca.example; accounturi=...`.
 * Returns the issuer domain ("" means "no CA may issue") or undefined if malformed.
 */
export function caaIssuer(value: string): string | undefined {
  const issuer = (value.split(";", 1)[0] ?? "").trim();
  if (issuer === "") return "";
  const labels = issuer.split(".");
  const valid = labels.length >= 2 && labels.every((l) => isDnsLabel(l) && !l.includes("_"));
  return valid ? issuer.toLowerCase() : undefined;
}

function describeIssuers(records: readonly CaaRecord[], tag: string): string[] {
  return records
    .filter((r) => r.tag === tag)
    .map((r) => {
      const issuer = caaIssuer(r.value);
      return issuer === "" ? "(none)" : (issuer ?? `invalid "${r.value}"`);
    });
}

export function checkCaa(observation: CaaObservation): Finding {
  const { records, foundAt, domain } = observation;
  const base = { check: CAA_CHECK, weight: CAA_WEIGHT };
  if (foundAt === undefined) {
    return makeFinding({
      ...base,
      status: Status.Warn,
      detail: `No CAA record on ${domain} or its parents: any public CA may issue certificates for it.`,
      recommendation: `Publish CAA records naming the CAs you use, e.g. \`${domain}. CAA 0 issue "letsencrypt.org"\`, plus \`0 iodef "mailto:security@${domain}"\` for violation reports.`,
    });
  }
  const where = foundAt === domain ? "" : ` (inherited from ${foundAt})`;
  const criticalUnknown = records.filter((r) => r.critical && !KNOWN_CAA_TAGS.has(r.tag));
  if (criticalUnknown.length > 0) {
    const tags = [...new Set(criticalUnknown.map((r) => r.tag))].join(", ");
    return makeFinding({
      ...base,
      status: Status.Warn,
      score: PARTIAL,
      detail: `CAA${where} has unknown critical tag(s) ${tags}; CAs that don't understand them must refuse to issue.`,
      recommendation:
        "Clear the critical flag (use 0 instead of 128) unless every CA you use supports the tag, or certificate renewals may fail.",
    });
  }
  const issue = describeIssuers(records, "issue");
  const issuewild = describeIssuers(records, "issuewild");
  if (issue.length === 0) {
    // RFC 8659 §4.2: without an issue property, non-wildcard issuance is unrestricted.
    const scope =
      issuewild.length > 0
        ? "only restricts wildcard certificates"
        : "doesn't restrict which CAs may issue";
    return makeFinding({
      ...base,
      status: Status.Warn,
      score: PARTIAL,
      detail: `CAA${where} has no issue property, so it ${scope}.`,
      recommendation: 'Add an issue property naming your CA, e.g. `0 issue "letsencrypt.org"`.',
    });
  }
  const invalid = [...issue, ...issuewild].filter((v) => v.startsWith("invalid"));
  const parts = [`issue: ${issue.join(", ")}`];
  if (issuewild.length > 0) parts.push(`issuewild: ${issuewild.join(", ")}`);
  if (invalid.length > 0) {
    return makeFinding({
      ...base,
      status: Status.Warn,
      score: PARTIAL,
      detail: `CAA${where} restricts issuance but has malformed values (${parts.join("; ")}).`,
      recommendation:
        'Each issue value must be a CA domain, optionally followed by parameters: `0 issue "ca.example; accounturi=..."`.',
    });
  }
  const hasIodef = records.some((r) => r.tag === "iodef");
  return makeFinding({
    ...base,
    status: Status.Pass,
    score: CAA_WEIGHT,
    detail: `CAA${where} restricts issuance (${parts.join("; ")}).`,
    recommendation: hasIodef
      ? ""
      : 'Consider an iodef property (`0 iodef "mailto:security@example.com"`) so CAs can report refused requests.',
  });
}
