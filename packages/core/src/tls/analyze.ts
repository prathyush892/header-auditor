/**
 * Pure TLS checks: each takes a `TlsSnapshot` (or part of one) and returns a
 * Finding. No sockets here; see `probe.ts` for how the snapshot is gathered.
 */
import { checkServerIdentity, type PeerCertificate } from "node:tls";
import { makeFinding, Status, type Finding } from "../finding.js";
import { scoreFindings, type Score } from "../report.js";
import {
  LEGACY_VERSIONS,
  type CertificateInfo,
  type CipherInfo,
  type LegacyVersion,
  type TlsSnapshot,
} from "./types.js";

const DAY_MS = 86_400_000;

export const DEFAULT_EXPIRY_WARN_DAYS = 30;
export const DEFAULT_EXPIRY_CRITICAL_DAYS = 7;
export const MIN_RSA_BITS = 2048;
export const MIN_EC_BITS = 256;

const WEIGHTS = {
  protocol: 15,
  legacy: 15,
  cipher: 15,
  validity: 20,
  hostname: 20,
  trust: 15,
  key: 10,
} as const;

export interface TlsAnalyzeOptions {
  /** Clock used for expiry maths; injectable so tests don't depend on today. */
  now?: Date;
  /** Warn when the certificate expires within this many days. Default 30. */
  expiryWarnDays?: number;
  /** Fail when it expires within this many days. Default 7. */
  expiryCriticalDays?: number;
}

interface ExpiryThresholds {
  now: Date;
  warnDays: number;
  criticalDays: number;
}

function resolveThresholds(options: TlsAnalyzeOptions): ExpiryThresholds {
  const now = options.now ?? new Date();
  if (Number.isNaN(now.getTime())) throw new RangeError("now must be a valid Date");
  const warnDays = options.expiryWarnDays ?? DEFAULT_EXPIRY_WARN_DAYS;
  const criticalDays = options.expiryCriticalDays ?? DEFAULT_EXPIRY_CRITICAL_DAYS;
  for (const [name, value] of [
    ["expiryWarnDays", warnDays],
    ["expiryCriticalDays", criticalDays],
  ] as const) {
    if (!Number.isInteger(value) || value < 0 || value > 3650) {
      throw new RangeError(`${name} must be an integer between 0 and 3650`);
    }
  }
  if (criticalDays > warnDays) {
    throw new RangeError("expiryCriticalDays must not exceed expiryWarnDays");
  }
  return { now, warnDays, criticalDays };
}

/** Throws RangeError if the expiry options or clock are invalid. */
export function validateAnalyzeOptions(options: TlsAnalyzeOptions): void {
  resolveThresholds(options);
}

// ---------------------------------------------------------------- protocol

export function checkTlsProtocol(protocol: string): Finding {
  const check = "TLS protocol";
  if (protocol === "TLSv1.3" || protocol === "TLSv1.2") {
    return makeFinding({
      check,
      status: Status.Pass,
      detail: `Negotiated ${protocol}.`,
      weight: WEIGHTS.protocol,
      score: WEIGHTS.protocol,
      recommendation: protocol === "TLSv1.2" ? "Consider enabling TLS 1.3 as well." : "",
    });
  }
  return makeFinding({
    check,
    status: Status.Fail,
    detail: `Best protocol the server offers is ${protocol}, which is deprecated (RFC 8996).`,
    weight: WEIGHTS.protocol,
    recommendation: "Support TLS 1.2 and TLS 1.3 and disable everything older.",
  });
}

export function checkLegacyProtocols(
  legacy: Readonly<Record<LegacyVersion, "accepted" | "rejected" | "untested">>,
): Finding {
  const check = "Legacy TLS versions";
  const results = new Map<LegacyVersion, string>(
    Object.entries(legacy) as [LegacyVersion, string][],
  );
  const accepted = LEGACY_VERSIONS.filter((v) => results.get(v) === "accepted");
  const untested = LEGACY_VERSIONS.filter((v) => (results.get(v) ?? "untested") === "untested");
  if (accepted.length > 0) {
    return makeFinding({
      check,
      status: Status.Fail,
      detail: `Server still accepts ${accepted.join(" and ")}.`,
      weight: WEIGHTS.legacy,
      recommendation:
        "Disable TLS 1.0 and 1.1 (e.g. nginx `ssl_protocols TLSv1.2 TLSv1.3;`). They lack modern ciphers and are deprecated by RFC 8996.",
    });
  }
  if (untested.length === LEGACY_VERSIONS.length) {
    return makeFinding({
      check,
      status: Status.Info,
      detail: "Could not test whether TLS 1.0/1.1 are accepted.",
    });
  }
  const suffix = untested.length > 0 ? ` (${untested.join(", ")} could not be tested)` : "";
  return makeFinding({
    check,
    status: Status.Pass,
    detail: `TLS 1.0 and 1.1 are refused${suffix}.`,
    weight: WEIGHTS.legacy,
    score: WEIGHTS.legacy,
  });
}

// ------------------------------------------------------------------ cipher

export type CipherStrength = "insecure" | "no-forward-secrecy" | "cbc" | "strong";

const INSECURE_CIPHER =
  /(^|[-_])(NULL|EXP(ORT)?|RC4|RC2|DES|3DES|DES-CBC3|MD5|ANON|ADH|AECDH|IDEA)([-_]|$)/i;

/**
 * Classifies a negotiated suite. TLS 1.3 suites (`TLS_AES_*`, `TLS_CHACHA20_*`)
 * are always forward-secret AEAD. For TLS 1.2 and older, the key exchange is in
 * the name: only (EC)DHE gives forward secrecy, and only GCM/CCM/ChaCha20 are AEAD.
 */
export function classifyCipher(cipher: CipherInfo): CipherStrength {
  const names = `${cipher.name} ${cipher.standardName}`;
  if (INSECURE_CIPHER.test(cipher.name) || INSECURE_CIPHER.test(cipher.standardName)) {
    return "insecure";
  }
  if (/^TLS_(AES|CHACHA20)_/i.test(cipher.name)) return "strong";
  if (!/(^|[-_])(ECDHE|DHE|EDH)([-_]|$)/i.test(names)) return "no-forward-secrecy";
  if (!/(GCM|CCM|CHACHA20|POLY1305)/i.test(names)) return "cbc";
  return "strong";
}

export function checkCipher(cipher: CipherInfo): Finding {
  const check = "Cipher suite";
  const label = cipher.standardName || cipher.name;
  switch (classifyCipher(cipher)) {
    case "insecure":
      return makeFinding({
        check,
        status: Status.Fail,
        detail: `Negotiated ${label}, which is broken (NULL/export/RC4/DES/anonymous/MD5).`,
        weight: WEIGHTS.cipher,
        recommendation: "Remove these suites; offer only ECDHE with AES-GCM or ChaCha20-Poly1305.",
      });
    case "no-forward-secrecy":
      return makeFinding({
        check,
        status: Status.Warn,
        detail: `Negotiated ${label}, which uses static RSA key exchange (no forward secrecy).`,
        weight: WEIGHTS.cipher,
        score: 5,
        recommendation:
          "Prefer ECDHE suites so a leaked private key can't decrypt recorded traffic.",
      });
    case "cbc":
      return makeFinding({
        check,
        status: Status.Warn,
        detail: `Negotiated ${label}, a CBC-mode suite (historically prone to padding-oracle bugs).`,
        weight: WEIGHTS.cipher,
        score: 10,
        recommendation: "Prefer AEAD suites (AES-GCM, ChaCha20-Poly1305).",
      });
    case "strong":
      return makeFinding({
        check,
        status: Status.Pass,
        detail: `Negotiated ${label}.`,
        weight: WEIGHTS.cipher,
        score: WEIGHTS.cipher,
      });
  }
}

// ------------------------------------------------------------- certificate

function missingCertificate(check: string, weight: number): Finding {
  return makeFinding({
    check,
    status: Status.Fail,
    detail: "Server did not present a certificate.",
    weight,
    recommendation: "Configure a certificate from a trusted CA.",
  });
}

function isoDate(date: Date): string {
  return date.toISOString().slice(0, 10);
}

export function checkCertificateValidity(
  cert: CertificateInfo | undefined,
  options: TlsAnalyzeOptions = {},
): Finding {
  const check = "Certificate validity";
  const weight = WEIGHTS.validity;
  if (!cert) return missingCertificate(check, weight);
  const { now, warnDays, criticalDays } = resolveThresholds(options);
  const renew = "Renew the certificate and automate renewal (e.g. ACME / Let's Encrypt).";

  if (now < cert.validFrom) {
    return makeFinding({
      check,
      status: Status.Fail,
      detail: `Certificate is not valid until ${isoDate(cert.validFrom)}.`,
      weight,
      recommendation: "Check the server clock and the certificate's notBefore date.",
    });
  }
  const daysLeft = Math.floor((cert.validTo.getTime() - now.getTime()) / DAY_MS);
  if (now > cert.validTo) {
    return makeFinding({
      check,
      status: Status.Fail,
      detail: `Certificate expired on ${isoDate(cert.validTo)}.`,
      weight,
      recommendation: renew,
    });
  }
  if (daysLeft <= criticalDays) {
    return makeFinding({
      check,
      status: Status.Fail,
      detail: `Certificate expires in ${String(daysLeft)} day(s), on ${isoDate(cert.validTo)}.`,
      weight,
      score: 5,
      recommendation: renew,
    });
  }
  if (daysLeft <= warnDays) {
    return makeFinding({
      check,
      status: Status.Warn,
      detail: `Certificate expires in ${String(daysLeft)} days, on ${isoDate(cert.validTo)}.`,
      weight,
      score: 12,
      recommendation: renew,
    });
  }
  return makeFinding({
    check,
    status: Status.Pass,
    detail: `Valid until ${isoDate(cert.validTo)} (${String(daysLeft)} days left).`,
    weight,
    score: weight,
  });
}

/**
 * Uses Node's own `checkServerIdentity` (RFC 6125 rules: SAN wins over CN,
 * one-label wildcards only, IPs must be in an IP SAN) rather than a hand-rolled
 * matcher, so the scanner agrees with what Node clients would accept.
 */
export function certificateMatchesHost(hostname: string, cert: CertificateInfo): boolean {
  const peer = {
    subject: cert.subjectCommonName === undefined ? {} : { CN: cert.subjectCommonName },
    subjectaltname: cert.subjectAltName,
  } as unknown as PeerCertificate;
  return checkServerIdentity(hostname, peer) === undefined;
}

export function checkCertificateHostname(
  hostname: string,
  cert: CertificateInfo | undefined,
): Finding {
  const check = "Certificate hostname";
  const weight = WEIGHTS.hostname;
  if (!cert) return missingCertificate(check, weight);
  if (certificateMatchesHost(hostname, cert)) {
    return makeFinding({
      check,
      status: Status.Pass,
      detail: `Certificate is valid for ${hostname}.`,
      weight,
      score: weight,
    });
  }
  const names = cert.subjectAltName ?? `CN=${cert.subjectCommonName ?? "(none)"}`;
  return makeFinding({
    check,
    status: Status.Fail,
    detail: `Certificate does not cover ${hostname} (it lists ${names}).`,
    weight,
    recommendation: `Issue a certificate whose subjectAltName includes ${hostname}.`,
  });
}

const SELF_SIGNED_ERRORS = new Set(["DEPTH_ZERO_SELF_SIGNED_CERT", "SELF_SIGNED_CERT_IN_CHAIN"]);
const VALIDITY_ERRORS = new Set(["CERT_HAS_EXPIRED", "CERT_NOT_YET_VALID"]);

export function checkCertificateTrust(snapshot: TlsSnapshot): Finding {
  const check = "Certificate trust";
  const weight = WEIGHTS.trust;
  const cert = snapshot.certificate;
  if (!cert) return missingCertificate(check, weight);
  const issuer = cert.issuerOrganization ?? cert.issuerCommonName ?? "unknown issuer";
  if (snapshot.authorized) {
    return makeFinding({
      check,
      status: Status.Pass,
      detail: `Chain verifies to a trusted root (issued by ${issuer}).`,
      weight,
      score: weight,
    });
  }
  const code = snapshot.authorizationError ?? "UNKNOWN";
  if (VALIDITY_ERRORS.has(code)) {
    // OpenSSL reports the first error only; the date problem is scored by the
    // validity check, so don't count it twice, but don't claim full trust either.
    return makeFinding({
      check,
      status: Status.Warn,
      detail: `Chain could not be fully verified (${code}); issued by ${issuer}.`,
      weight,
      score: 8,
      recommendation: "Renew the certificate, then re-scan to confirm the chain.",
    });
  }
  if (SELF_SIGNED_ERRORS.has(code) || (cert.selfIssued && code !== "UNKNOWN")) {
    return makeFinding({
      check,
      status: Status.Fail,
      detail: `Certificate is self-signed (${code}); browsers will show an interstitial.`,
      weight,
      recommendation: "Use a certificate issued by a publicly trusted CA.",
    });
  }
  return makeFinding({
    check,
    status: Status.Fail,
    detail: `Chain is not trusted (${code}); issued by ${issuer}.`,
    weight,
    recommendation:
      "Serve the full intermediate chain and use a certificate from a publicly trusted CA.",
  });
}

export function checkCertificateKey(cert: CertificateInfo | undefined): Finding {
  const check = "Certificate key";
  const weight = WEIGHTS.key;
  if (!cert) return missingCertificate(check, weight);
  const bits = cert.keyBits;
  if (cert.keyType === "unknown" || bits === undefined) {
    return makeFinding({ check, status: Status.Info, detail: "Key type or size not reported." });
  }
  const minimum = cert.keyType === "RSA" ? MIN_RSA_BITS : MIN_EC_BITS;
  if (bits < minimum) {
    return makeFinding({
      check,
      status: Status.Fail,
      detail: `${cert.keyType} ${String(bits)}-bit key is below the ${String(minimum)}-bit minimum.`,
      weight,
      recommendation: "Re-key with RSA 2048+ or ECDSA P-256.",
    });
  }
  return makeFinding({
    check,
    status: Status.Pass,
    detail: `${cert.keyType} ${String(bits)}-bit key.`,
    weight,
    score: weight,
  });
}

// ------------------------------------------------------------------ report

/** Runs every TLS check in a fixed order. Throws RangeError on bad options. */
export function analyzeTls(snapshot: TlsSnapshot, options: TlsAnalyzeOptions = {}): Finding[] {
  validateAnalyzeOptions(options);
  return [
    checkTlsProtocol(snapshot.protocol),
    checkLegacyProtocols(snapshot.legacy),
    checkCipher(snapshot.cipher),
    checkCertificateValidity(snapshot.certificate, options),
    checkCertificateHostname(snapshot.hostname, snapshot.certificate),
    checkCertificateTrust(snapshot),
    checkCertificateKey(snapshot.certificate),
  ];
}

export interface TlsReport extends Score {
  readonly host: string;
  readonly port: number;
  readonly snapshot: TlsSnapshot;
  readonly findings: readonly Finding[];
  /**
   * Checks that forced the grade to F regardless of the score, because a
   * browser would refuse the connection outright. Empty when not capped.
   */
  readonly gradeCappedBy: readonly string[];
}

/** Failing any of these with zero points means browsers show a hard error. */
const BLOCKING_CHECKS: ReadonlySet<string> = new Set([
  "TLS protocol",
  "Certificate validity",
  "Certificate hostname",
  "Certificate trust",
]);

/**
 * Points can't express "browsers refuse this": a self-signed certificate with
 * a great cipher would still average out to a passing grade. So, like SSL
 * Labs, a zero-score failure on a blocking check caps the grade at F while
 * the numeric score stays visible for comparing scans.
 */
export function blockingFailures(findings: readonly Finding[]): string[] {
  return findings
    .filter((f) => BLOCKING_CHECKS.has(f.check) && f.status === "fail" && f.score === 0)
    .map((f) => f.check);
}

export function buildTlsReport(snapshot: TlsSnapshot, options: TlsAnalyzeOptions = {}): TlsReport {
  const findings = analyzeTls(snapshot, options);
  const score = scoreFindings(findings);
  const cappedBy = blockingFailures(findings);
  return Object.freeze({
    host: snapshot.hostname,
    port: snapshot.port,
    snapshot,
    findings: Object.freeze(findings),
    ...score,
    grade: cappedBy.length > 0 ? "F" : score.grade,
    gradeCappedBy: Object.freeze(cappedBy),
  });
}
