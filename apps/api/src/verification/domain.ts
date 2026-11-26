/**
 * Domain-ownership verification with a DNS TXT record.
 *
 * Each site has a random `verificationToken`. To prove control of the site's
 * hostname, the owner publishes
 *
 *   _header-auditor-challenge.<hostname>  TXT  "header-auditor-verification=<token>"
 *
 * and asks the API to check. Only someone who can edit the zone can create
 * that record, and the token is unique per site, so it shows that *this*
 * account (not just anyone who added the same URL) controls the domain.
 *
 * This module is pure apart from the injected `DnsResolver`: the record
 * name, the expected value and the evaluation of the answer are plain
 * functions, so tests cover every outcome without a network.
 */
import {
  type DnsErrorCode,
  type DnsResolver,
  isDnsLookupError,
  normalizeDomain,
} from "@header-auditor/core";

/**
 * Underscore label (RFC 8552 "attrleaf"), like `_acme-challenge` or
 * `_dmarc`: it can't clash with a real hostname, with the apex TXT records
 * (SPF lives there) or with a CNAME at the hostname itself.
 */
export const VERIFICATION_RECORD_LABEL = "_header-auditor-challenge";
export const VERIFICATION_VALUE_PREFIX = "header-auditor-verification=";

/** Bound on TXT strings looked at, so a zone full of records can't make one check expensive. */
export const MAX_TXT_RECORDS_EXAMINED = 50;

export interface VerificationRecord {
  /** Fully qualified record name, e.g. `_header-auditor-challenge.www.example.com`. */
  readonly name: string;
  readonly type: "TXT";
  /** Exact TXT value to publish. */
  readonly value: string;
}

/** The site's host can't be verified over DNS (an IP literal, `localhost`, ...). */
export class VerificationUnsupportedError extends Error {
  override readonly name = "VerificationUnsupportedError";
}

export type VerificationOutcome =
  | { readonly status: "VERIFIED" }
  /** No TXT record at the name starts with our prefix. */
  | { readonly status: "RECORD_MISSING" }
  /** A record with our prefix exists but carries another token (old site, typo). */
  | { readonly status: "TOKEN_MISMATCH" }
  /** The lookup itself failed (timeout, SERVFAIL...): no conclusion either way. */
  | { readonly status: "DNS_ERROR"; readonly code: DnsErrorCode };

export type VerificationResult = VerificationOutcome & { readonly record: VerificationRecord };

export interface DomainVerifier {
  /** @throws VerificationUnsupportedError when the URL's host has no DNS name to check. */
  verify(siteUrl: string, token: string): Promise<VerificationResult>;
}

const TOKEN = /^[0-9a-f]{64}$/;

function hostnameOf(siteUrl: string): string {
  let url: URL;
  try {
    url = new URL(siteUrl);
  } catch {
    throw new VerificationUnsupportedError("Site URL is not a valid URL");
  }
  return url.hostname;
}

/**
 * The record a site's owner must publish. Exact hostname only: verifying
 * `www.example.com` says nothing about `example.com`, and a parent record
 * doesn't cover children, so someone who controls one subdomain (a user page
 * on a shared host, say) can't claim its siblings or its parent.
 *
 * @throws VerificationUnsupportedError for IP literals and single-label hosts.
 */
export function verificationRecord(siteUrl: string, token: string): VerificationRecord {
  if (!TOKEN.test(token))
    throw new RangeError("verification token must be 64 lower-case hex chars");
  let domain: string;
  try {
    domain = normalizeDomain(hostnameOf(siteUrl));
  } catch (error) {
    if (error instanceof VerificationUnsupportedError) throw error;
    throw new VerificationUnsupportedError(
      "Only sites with a DNS hostname can be verified (not IP addresses or localhost)",
    );
  }
  return {
    name: `${VERIFICATION_RECORD_LABEL}.${domain}`,
    type: "TXT",
    value: `${VERIFICATION_VALUE_PREFIX}${token}`,
  };
}

/** Like `verificationRecord`, but null instead of throwing (for the public site JSON). */
export function verificationRecordOrNull(
  siteUrl: string,
  token: string,
): VerificationRecord | null {
  try {
    return verificationRecord(siteUrl, token);
  } catch (error) {
    if (error instanceof VerificationUnsupportedError || error instanceof RangeError) return null;
    throw error;
  }
}

/**
 * Decides the outcome from the TXT strings found at the record name. Any one
 * exact match verifies, so several accounts (or a token rotation) can each
 * have their own record side by side. Surrounding whitespace is forgiven
 * (some DNS panels add it); anything else must match byte for byte.
 */
export function evaluateTxtRecords(
  records: readonly string[],
  record: VerificationRecord,
): VerificationOutcome {
  let sawPrefix = false;
  for (const raw of records.slice(0, MAX_TXT_RECORDS_EXAMINED)) {
    const value = raw.trim();
    if (value === record.value) return { status: "VERIFIED" };
    if (value.toLowerCase().startsWith(VERIFICATION_VALUE_PREFIX)) sawPrefix = true;
  }
  return { status: sawPrefix ? "TOKEN_MISMATCH" : "RECORD_MISSING" };
}

export function createDomainVerifier(resolver: DnsResolver): DomainVerifier {
  return {
    async verify(siteUrl, token) {
      const record = verificationRecord(siteUrl, token);
      let records: readonly string[];
      try {
        records = await resolver.txt(record.name);
      } catch (error) {
        if (isDnsLookupError(error)) return { status: "DNS_ERROR", code: error.code, record };
        throw error;
      }
      return { ...evaluateTxtRecords(records, record), record };
    },
  };
}
