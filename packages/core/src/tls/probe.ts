/**
 * `probeTls()`: opens TLS handshakes to an https target and records what it
 * saw as a `TlsSnapshot`, then grades it with the pure checks in `analyze.ts`.
 *
 * Safety properties shared with `scanUrl()`:
 * - The same SSRF policy: IP literals are checked up front, hostnames inside
 *   the socket's own DNS lookup (so DNS rebinding can't swap the address).
 * - One deadline for every handshake, plus caller cancellation.
 * - Handshake only. No application data is ever written to the server.
 *
 * Certificate verification is *observed*, not enforced (`rejectUnauthorized:
 * false`): a scanner has to complete the handshake with a broken certificate
 * to report on it. That is safe here only because nothing is sent afterwards.
 */
import { connect, type ConnectionOptions, type PeerCertificate, type TLSSocket } from "node:tls";
import { isIP } from "node:net";
import { parseAllowList, type AddressPolicy } from "../scan/address.js";
import { ScanError, type ScanErrorCode } from "../scan/errors.js";
import {
  createGuardedLookup,
  systemResolver,
  type LookupOutcome,
  type Resolver,
} from "../scan/lookup.js";
import {
  DEFAULT_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
  normalizeCaOption,
  validateTarget,
} from "../scan/scan-url.js";
import {
  buildTlsReport,
  validateAnalyzeOptions,
  type TlsAnalyzeOptions,
  type TlsReport,
} from "./analyze.js";
import {
  type CertificateInfo,
  type KeyType,
  type LegacyProbeResult,
  type LegacyVersion,
  type TlsSnapshot,
} from "./types.js";

/**
 * OpenSSL security level 0 lets the probe complete handshakes with weak
 * servers (old protocols, small keys) so it can *report* them. It is only
 * ever used for these read-only handshakes, never for fetching content.
 */
const PROBE_CIPHERS = "DEFAULT@SECLEVEL=0";

export interface TlsProbeOptions extends TlsAnalyzeOptions {
  /** Total time budget for every handshake together. Default 10 s. */
  timeoutMs?: number;
  /** Also offer TLS 1.0 and 1.1 on their own to see if they're accepted. Default true. */
  probeLegacy?: boolean;
  allowPrivate?: boolean;
  allowAddresses?: readonly string[];
  resolver?: Resolver;
  /** PEM CA certificate(s) to trust *instead of* the system roots (private PKI, tests). */
  ca?: string | readonly string[];
  signal?: AbortSignal;
}

interface ProbeContext {
  host: string;
  port: number;
  servername: string | undefined;
  policy: AddressPolicy;
  resolver: Resolver;
  ca: string[] | undefined;
  deadline: AbortSignal;
  external: AbortSignal | undefined;
  url: string;
}

interface Handshake {
  protocol: string;
  cipher: { name: string; standardName: string };
  peer: PeerCertificate;
  authorized: boolean;
  authorizationError: string | undefined;
}

function invalidOption(message: string): ScanError {
  return new ScanError("INVALID_OPTIONS", message);
}

function errorCode(err: unknown): string | undefined {
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === "string" ? code : undefined;
}

/** TLS handshake failures the server caused (as opposed to our own setup or the network). */
function isHandshakeRejection(err: unknown): boolean {
  const code = errorCode(err) ?? "";
  if (code === "ERR_SSL_NO_PROTOCOLS_AVAILABLE") return false; // our OpenSSL can't offer it
  return code.startsWith("ERR_SSL_") || code === "ECONNRESET" || code === "EPROTO";
}

function toScanError(err: unknown, ctx: ProbeContext, outcome: LookupOutcome): ScanError {
  if (err instanceof ScanError) return err;
  const fail = (code: ScanErrorCode, message: string): ScanError =>
    new ScanError(code, message, { url: ctx.url, cause: err });
  if (outcome.blocked) {
    return fail(
      "BLOCKED_ADDRESS",
      `${outcome.blocked.hostname} resolves to ${outcome.blocked.address}, which is not allowed`,
    );
  }
  if (ctx.external?.aborted) return fail("ABORTED", "Scan was aborted");
  if (ctx.deadline.aborted) return fail("TIMEOUT", "TLS handshake timed out");
  if (outcome.dnsError !== undefined) return fail("DNS_FAILURE", `Could not resolve ${ctx.host}`);
  const detail = err instanceof Error ? err.message : String(err);
  if (isHandshakeRejection(err)) return fail("TLS_ERROR", `TLS handshake failed: ${detail}`);
  return fail("NETWORK", `Connection failed: ${detail}`);
}

/** One handshake. Resolves once it completes, then closes the socket without writing. */
function handshake(
  ctx: ProbeContext,
  outcome: LookupOutcome,
  versions: Pick<ConnectionOptions, "minVersion" | "maxVersion">,
): Promise<Handshake> {
  const signal = ctx.external ? AbortSignal.any([ctx.deadline, ctx.external]) : ctx.deadline;
  return new Promise<Handshake>((resolve, reject) => {
    if (signal.aborted) {
      reject(new Error("aborted before connect"));
      return;
    }
    const socket: TLSSocket = connect({
      host: ctx.host,
      port: ctx.port,
      servername: ctx.servername,
      lookup: createGuardedLookup(ctx.resolver, ctx.policy, outcome),
      rejectUnauthorized: false,
      ciphers: PROBE_CIPHERS,
      ca: ctx.ca,
      ...versions,
    });
    const onAbort = (): void => {
      socket.destroy(new Error("aborted"));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    const cleanup = (): void => {
      signal.removeEventListener("abort", onAbort);
    };
    socket.once("secureConnect", () => {
      cleanup();
      const cipher = socket.getCipher();
      const authError = socket.authorizationError as unknown;
      const result: Handshake = {
        protocol: socket.getProtocol() ?? "unknown",
        cipher: { name: cipher.name, standardName: cipher.standardName },
        peer: socket.getPeerCertificate(false),
        authorized: socket.authorized,
        authorizationError:
          authError instanceof Error
            ? (errorCode(authError) ?? authError.message)
            : typeof authError === "string"
              ? authError
              : undefined,
      };
      // The result is settled; a reset while closing must not surface as an
      // unhandled 'error' event.
      socket.on("error", () => undefined);
      socket.end();
      resolve(result);
    });
    socket.once("error", (err: Error) => {
      cleanup();
      socket.destroy();
      reject(err);
    });
  });
}

async function probeLegacyVersion(
  ctx: ProbeContext,
  version: LegacyVersion,
): Promise<LegacyProbeResult> {
  try {
    await handshake(ctx, {}, { minVersion: version, maxVersion: version });
    return "accepted";
  } catch (err) {
    if (ctx.deadline.aborted || ctx.external?.aborted) return "untested";
    return isHandshakeRejection(err) ? "rejected" : "untested";
  }
}

function firstValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function parseCertDate(raw: string | undefined, field: string): Date {
  const date = new Date(raw ?? "");
  if (Number.isNaN(date.getTime())) {
    throw new ScanError("TLS_ERROR", `Certificate has an unreadable ${field} date`);
  }
  return date;
}

/** Flattens Node's PeerCertificate into the plain data the checks need. */
export function certificateInfo(peer: PeerCertificate): CertificateInfo | undefined {
  if (Object.keys(peer).length === 0) return undefined;
  const loose = peer as PeerCertificate & {
    asn1Curve?: string;
    nistCurve?: string;
    modulus?: string;
  };
  let keyType: KeyType = "unknown";
  if (typeof loose.modulus === "string") keyType = "RSA";
  else if (loose.asn1Curve !== undefined || loose.nistCurve !== undefined) keyType = "EC";
  const subject = peer.subject as Record<string, string | string[] | undefined> | undefined;
  const issuer = peer.issuer as Record<string, string | string[] | undefined> | undefined;
  return Object.freeze({
    subjectCommonName: firstValue(subject?.CN),
    subjectAltName: typeof peer.subjectaltname === "string" ? peer.subjectaltname : undefined,
    issuerCommonName: firstValue(issuer?.CN),
    issuerOrganization: firstValue(issuer?.O),
    validFrom: parseCertDate(peer.valid_from, "notBefore"),
    validTo: parseCertDate(peer.valid_to, "notAfter"),
    keyType,
    keyBits: typeof peer.bits === "number" && peer.bits > 0 ? peer.bits : undefined,
    selfIssued: JSON.stringify(peer.subject) === JSON.stringify(peer.issuer),
    fingerprint256: peer.fingerprint256,
  });
}

function buildContext(
  rawUrl: string,
  options: TlsProbeOptions,
  deadline: AbortSignal,
): ProbeContext {
  let allowList;
  try {
    allowList = parseAllowList(options.allowAddresses ?? []);
  } catch (err) {
    throw invalidOption(err instanceof Error ? err.message : String(err));
  }
  const policy: AddressPolicy = { allowPrivate: options.allowPrivate ?? false, allowList };
  const url = validateTarget(rawUrl, policy);
  if (url.protocol !== "https:") {
    throw new ScanError("INVALID_URL", "TLS checks need an https:// URL", { url: url.href });
  }
  const host = url.hostname.replace(/^\[(.*)\]$/, "$1");
  return {
    host,
    port: url.port === "" ? 443 : Number(url.port),
    // SNI must be a DNS name; RFC 6066 forbids IP literals there.
    servername: isIP(host) === 0 ? host : undefined,
    policy,
    resolver: options.resolver ?? systemResolver,
    ca: normalizeCaOption(options.ca),
    deadline,
    external: options.signal,
    url: url.href,
  };
}

/**
 * Handshakes with `rawUrl`'s host and grades its TLS setup: negotiated
 * protocol and cipher, legacy-version acceptance, and the leaf certificate's
 * validity window, hostname match, chain trust and key size.
 *
 * @throws ScanError (INVALID_URL, INVALID_OPTIONS, BLOCKED_*, DNS_FAILURE,
 *   TIMEOUT, ABORTED, TLS_ERROR, NETWORK). A bad certificate is a *finding*,
 *   not an error; TLS_ERROR means no handshake could be completed at all.
 */
export async function probeTls(rawUrl: string, options: TlsProbeOptions = {}): Promise<TlsReport> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMEOUT_MS) {
    throw invalidOption(`timeoutMs must be an integer between 1 and ${String(MAX_TIMEOUT_MS)}`);
  }
  // Validate analysis options before opening any socket.
  try {
    validateAnalyzeOptions(options);
  } catch (err) {
    throw invalidOption(err instanceof Error ? err.message : String(err));
  }
  const ctx = buildContext(rawUrl, options, AbortSignal.timeout(timeoutMs));

  const outcome: LookupOutcome = {};
  let main: Handshake;
  try {
    main = await handshake(ctx, outcome, { minVersion: "TLSv1", maxVersion: "TLSv1.3" });
  } catch (err) {
    throw toScanError(err, ctx, outcome);
  }

  const [tls10, tls11] =
    (options.probeLegacy ?? true)
      ? await Promise.all([probeLegacyVersion(ctx, "TLSv1"), probeLegacyVersion(ctx, "TLSv1.1")])
      : (["untested", "untested"] as const);
  // A server whose best protocol is legacy has, by definition, accepted it.
  const legacy: Record<LegacyVersion, LegacyProbeResult> = {
    TLSv1: main.protocol === "TLSv1" ? "accepted" : tls10,
    "TLSv1.1": main.protocol === "TLSv1.1" ? "accepted" : tls11,
  };

  const snapshot: TlsSnapshot = Object.freeze({
    hostname: ctx.host,
    port: ctx.port,
    protocol: main.protocol,
    cipher: Object.freeze(main.cipher),
    certificate: certificateInfo(main.peer),
    authorized: main.authorized,
    authorizationError: main.authorizationError,
    legacy: Object.freeze(legacy),
  });
  return buildTlsReport(snapshot, options);
}
