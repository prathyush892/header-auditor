/**
 * Runs the DNS checks for one domain and scores them as their own section,
 * like the TLS and content reports, so the header score keeps parity with the
 * Python CLI.
 */
import { makeFinding, Status, type Finding } from "../finding.js";
import { scoreFindings, type Score } from "../report.js";
import { CAA_CHECK, checkCaa, lookupCaa, type CaaObservation } from "./caa.js";
import { checkDmarc, DMARC_CHECK, lookupDmarc, type DmarcObservation } from "./dmarc.js";
import {
  createDnsResolver,
  isDnsLookupError,
  normalizeDomain,
  type DnsResolver,
} from "./resolver.js";
import { checkSpf, lookupSpf, SPF_CHECK, type SpfObservation } from "./spf.js";

export interface DnsAnalyzeOptions {
  /** Defaults to the system resolver (`createDnsResolver()`). Tests inject fixtures. */
  resolver?: DnsResolver;
  /** Organizational domain for DMARC discovery, if known (see `naiveOrganizationalDomain`). */
  organizationalDomain?: string;
}

export interface DnsReport extends Score {
  readonly domain: string;
  readonly findings: readonly Finding[];
  /** Raw observations, undefined when that lookup failed. */
  readonly caa: CaaObservation | undefined;
  readonly spf: SpfObservation | undefined;
  readonly dmarc: DmarcObservation | undefined;
}

/** Unscored finding for a check whose DNS lookup failed (timeout, SERVFAIL...). */
export function dnsUnavailable(check: string, err: unknown): Finding {
  const reason = isDnsLookupError(err) ? err.message : "lookup failed";
  return makeFinding({
    check,
    status: Status.Info,
    detail: `Could not be determined: ${reason}.`,
  });
}

type Outcome<T> = { ok: true; value: T } | { ok: false; error: unknown };

async function attempt<T>(run: () => Promise<T>): Promise<Outcome<T>> {
  try {
    return { ok: true, value: await run() };
  } catch (error) {
    if (!isDnsLookupError(error)) throw error;
    return { ok: false, error };
  }
}

function grade<T>(check: string, outcome: Outcome<T>, checker: (v: T) => Finding): Finding {
  return outcome.ok ? checker(outcome.value) : dnsUnavailable(check, outcome.error);
}

/**
 * CAA, SPF and DMARC for `domain`. A failed lookup turns that one check into
 * an unscored `info` finding instead of failing it: a flaky resolver is not
 * evidence the domain is misconfigured.
 */
export async function analyzeDns(
  domain: string,
  options: DnsAnalyzeOptions = {},
): Promise<DnsReport> {
  const name = normalizeDomain(domain);
  const orgDomain =
    options.organizationalDomain === undefined
      ? undefined
      : normalizeDomain(options.organizationalDomain);
  if (orgDomain !== undefined && name !== orgDomain && !name.endsWith(`.${orgDomain}`)) {
    throw new RangeError(`organizationalDomain ${orgDomain} is not a parent of ${name}`);
  }
  const resolver = options.resolver ?? createDnsResolver();
  const [caa, spf, dmarc] = await Promise.all([
    attempt(() => lookupCaa(name, resolver)),
    attempt(() => lookupSpf(name, resolver)),
    attempt(() => lookupDmarc(name, resolver, orgDomain)),
  ]);
  const findings = Object.freeze([
    grade(CAA_CHECK, caa, checkCaa),
    grade(SPF_CHECK, spf, checkSpf),
    grade(DMARC_CHECK, dmarc, checkDmarc),
  ]);
  return Object.freeze({
    domain: name,
    findings,
    caa: caa.ok ? caa.value : undefined,
    spf: spf.ok ? spf.value : undefined,
    dmarc: dmarc.ok ? dmarc.value : undefined,
    ...scoreFindings(findings),
  });
}
