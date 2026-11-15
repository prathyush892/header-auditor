/**
 * Plain-data description of one TLS endpoint, as observed by `probeTls()`.
 *
 * Keeping the observation separate from the grading means every TLS check is
 * a pure function of this snapshot: tests feed fixtures, and a stored snapshot
 * can be re-graded later when the rules change without reconnecting.
 */

/** Protocol names exactly as Node's `TLSSocket.getProtocol()` reports them. */
export const TLS_VERSIONS = ["SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"] as const;
export type TlsVersion = (typeof TLS_VERSIONS)[number];

/** Versions that are deprecated (RFC 8996) and probed for separately. */
export const LEGACY_VERSIONS = ["TLSv1", "TLSv1.1"] as const;
export type LegacyVersion = (typeof LEGACY_VERSIONS)[number];

/**
 * Outcome of offering *only* one legacy version:
 * - `accepted`: the server completed a handshake with it (bad).
 * - `rejected`: the server refused it with a TLS alert (good).
 * - `untested`: we couldn't tell (our own OpenSSL can't offer it, timeout, reset).
 */
export type LegacyProbeResult = "accepted" | "rejected" | "untested";

export interface CipherInfo {
  /** OpenSSL name, e.g. `ECDHE-RSA-AES128-GCM-SHA256` or `TLS_AES_256_GCM_SHA384`. */
  readonly name: string;
  /** IANA name, e.g. `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`. */
  readonly standardName: string;
}

export type KeyType = "RSA" | "EC" | "unknown";

export interface CertificateInfo {
  readonly subjectCommonName: string | undefined;
  /** Node's `subjectaltname` string, e.g. `DNS:example.com, IP Address:127.0.0.1`. */
  readonly subjectAltName: string | undefined;
  readonly issuerCommonName: string | undefined;
  readonly issuerOrganization: string | undefined;
  readonly validFrom: Date;
  readonly validTo: Date;
  readonly keyType: KeyType;
  /** Public key size in bits (RSA modulus or EC curve size), when known. */
  readonly keyBits: number | undefined;
  /** Subject and issuer are identical (a self-signed or root certificate). */
  readonly selfIssued: boolean;
  readonly fingerprint256: string;
}

export interface TlsSnapshot {
  /** Host the certificate must be valid for (brackets stripped from IPv6). */
  readonly hostname: string;
  readonly port: number;
  /** Negotiated protocol when we offered everything we support. */
  readonly protocol: string;
  readonly cipher: CipherInfo;
  /** Leaf certificate; undefined if the server sent none. */
  readonly certificate: CertificateInfo | undefined;
  /** Chain verified against the trust store (hostname is checked separately). */
  readonly authorized: boolean;
  /** OpenSSL verify code such as `DEPTH_ZERO_SELF_SIGNED_CERT`. */
  readonly authorizationError: string | undefined;
  readonly legacy: Readonly<Record<LegacyVersion, LegacyProbeResult>>;
}
