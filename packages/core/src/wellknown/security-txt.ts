/**
 * security.txt (RFC 9116): a machine-readable "how to report a vulnerability"
 * file at `/.well-known/security.txt`.
 *
 * Split like the DNS checks: `parseSecurityTxt()` turns the text into fields
 * and problems, `checkSecurityTxt()` grades an observation. Both are pure; the
 * fetching lives in `probe.ts`.
 */
import { makeFinding, Status, type Finding } from "../finding.js";
import type { WellKnownObservation } from "./observation.js";

export const SECURITY_TXT_CHECK = "security.txt";
export const SECURITY_TXT_WEIGHT = 10;
export const SECURITY_TXT_PATH = "/.well-known/security.txt";
/** RFC 9116 §3: "for legacy compatibility" a file at the top-level path. */
export const SECURITY_TXT_LEGACY_PATH = "/security.txt";
/** Bytes read. Real files are well under 2 KiB; anything near this is suspicious. */
export const SECURITY_TXT_MAX_BYTES = 32 * 1024;
/** RFC 9116 §2.5.5 recommends an Expires less than a year away. */
const MAX_RECOMMENDED_LIFETIME_MS = 366 * 24 * 60 * 60 * 1000;

/** Fields defined by RFC 9116 §2.5 (lower-cased). Others are allowed but ignored. */
export const KNOWN_SECURITY_TXT_FIELDS: readonly string[] = [
  "acknowledgments",
  "canonical",
  "contact",
  "encryption",
  "expires",
  "hiring",
  "policy",
  "preferred-languages",
];

/** Fields that may appear at most once (§2.5.4, §2.5.5, §2.5.8). */
const SINGLE_FIELDS: ReadonlySet<string> = new Set(["expires", "preferred-languages"]);
/** Fields whose values must be URIs. */
const URI_FIELDS: ReadonlySet<string> = new Set([
  "acknowledgments",
  "canonical",
  "contact",
  "encryption",
  "hiring",
  "policy",
]);

const PGP_SIGNED_HEADER = "-----BEGIN PGP SIGNED MESSAGE-----";
const PGP_SIGNATURE_HEADER = "-----BEGIN PGP SIGNATURE-----";

export type ProblemLevel = "error" | "warning";

export interface SecurityTxtProblem {
  readonly level: ProblemLevel;
  readonly message: string;
}

export interface SecurityTxtField {
  /** Field name lower-cased (names are case-insensitive, §2.4). */
  readonly name: string;
  readonly value: string;
  /** 1-based line number in the original text. */
  readonly line: number;
}

export interface ParsedSecurityTxt {
  readonly fields: readonly SecurityTxtField[];
  /** True when the file is an OpenPGP cleartext-signed message (not verified). */
  readonly signed: boolean;
  readonly problems: readonly SecurityTxtProblem[];
}

/** Drops a leading UTF-8 byte-order mark. */
export function stripBom(text: string): string {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

function problem(level: ProblemLevel, message: string): SecurityTxtProblem {
  return Object.freeze({ level, message });
}

/**
 * Strips OpenPGP cleartext-signature armour (RFC 4880 §7), returning the
 * signed body. Dash-escaped lines ("- -----") are unescaped. The signature is
 * not verified: that needs the owner's key, which the scanner doesn't have.
 */
function unwrapSigned(lines: readonly string[]): {
  body: { text: string; line: number }[];
  signed: boolean;
  problems: SecurityTxtProblem[];
} {
  const problems: SecurityTxtProblem[] = [];
  const numbered = lines.map((text, i) => ({ text, line: i + 1 }));
  const first = numbered.find((l) => l.text.trim() !== "");
  if (first?.text.trim() !== PGP_SIGNED_HEADER) {
    return { body: numbered, signed: false, problems };
  }
  // Armour headers ("Hash: SHA256") end at the first blank line after the header.
  const blank = numbered.findIndex((l) => l.line > first.line && l.text.trim() === "");
  const bodyStart = blank === -1 ? numbered.length : blank + 1;
  const sigIndex = numbered.findIndex(
    (l, idx) => idx >= bodyStart && l.text.trim() === PGP_SIGNATURE_HEADER,
  );
  if (sigIndex === -1) {
    problems.push(problem("error", "Signed message has no PGP signature block."));
  }
  const body = numbered
    .slice(bodyStart, sigIndex === -1 ? undefined : sigIndex)
    .map((l) => ({ line: l.line, text: l.text.startsWith("- ") ? l.text.slice(2) : l.text }));
  return { body, signed: sigIndex !== -1, problems };
}

/** True for a field name per RFC 5322 ftext: printable ASCII except ":" and space. */
function isFieldName(name: string): boolean {
  if (name.length === 0 || name.length > 64) return false;
  for (const ch of name) {
    const code = ch.charCodeAt(0);
    if (code < 33 || code > 126 || ch === ":") return false;
  }
  return true;
}

/** Parses `text` into fields. Never throws: anything malformed becomes a problem. */
export function parseSecurityTxt(text: string): ParsedSecurityTxt {
  const lines = stripBom(text).split(/\r?\n/);
  const { body, signed, problems } = unwrapSigned(lines);
  const fields: SecurityTxtField[] = [];
  let malformed = 0;
  for (const { text: raw, line } of body) {
    const trimmed = raw.trim();
    if (trimmed === "" || trimmed.startsWith("#")) continue;
    const colon = trimmed.indexOf(":");
    const name = colon === -1 ? "" : trimmed.slice(0, colon).trim();
    if (!isFieldName(name)) {
      malformed += 1;
      if (malformed <= 3) {
        problems.push(problem("error", `Line ${String(line)} is not a "Field: value" line.`));
      }
      continue;
    }
    fields.push(
      Object.freeze({ name: name.toLowerCase(), value: trimmed.slice(colon + 1).trim(), line }),
    );
  }
  if (malformed > 3) {
    problems.push(problem("error", `${String(malformed - 3)} more malformed lines.`));
  }
  return Object.freeze({
    fields: Object.freeze(fields),
    signed,
    problems: Object.freeze(problems),
  });
}

/** Parses an absolute URI, returning undefined for anything that isn't one. */
function parseUri(value: string): URL | undefined {
  try {
    return new URL(value);
  } catch {
    return undefined;
  }
}

/**
 * Parses an RFC 3339 / ISO 8601 date-time with an explicit offset
 * (`2027-01-31T23:59:59Z`, `...+05:00`). Date-only values are rejected:
 * the RFC requires the full form.
 */
export function parseExpires(value: string): Date | undefined {
  const v = value.toUpperCase();
  const date = v.slice(0, 10);
  const time = v.slice(11, 19);
  if (
    v.charAt(10) !== "T" ||
    !/^\d{4}-\d{2}-\d{2}$/.test(date) ||
    !/^\d{2}:\d{2}:\d{2}$/.test(time)
  ) {
    return undefined;
  }
  let rest = v.slice(19);
  if (rest.startsWith(".")) {
    let end = 1;
    while (end < rest.length && end <= 10 && rest.charAt(end) >= "0" && rest.charAt(end) <= "9")
      end += 1;
    if (end === 1) return undefined;
    rest = rest.slice(end);
  }
  if (rest !== "Z" && !/^[+-]\d{2}:\d{2}$/.test(rest)) return undefined;
  const [year, month, day] = date.split("-").map(Number) as [number, number, number];
  const [hour, minute, second] = time.split(":").map(Number) as [number, number, number];
  // Reject calendar overflow (Feb 30) instead of letting Date roll it over.
  const probe = new Date(Date.UTC(year, month - 1, day));
  if (probe.getUTCMonth() !== month - 1 || probe.getUTCDate() !== day) return undefined;
  if (hour > 23 || minute > 59 || second > 60) return undefined;
  const ms = Date.parse(v);
  return Number.isNaN(ms) ? undefined : new Date(ms);
}

/** What the probe found, plus the URL the file was requested at. */
export type SecurityTxtObservation = WellKnownObservation;

interface Evaluation {
  readonly contacts: readonly string[];
  readonly expires: Date | undefined;
  readonly problems: readonly SecurityTxtProblem[];
}

function validateFields(parsed: ParsedSecurityTxt, now: Date): Evaluation {
  const problems = [...parsed.problems];
  const counts = new Map<string, number>();
  for (const f of parsed.fields) counts.set(f.name, (counts.get(f.name) ?? 0) + 1);

  for (const name of SINGLE_FIELDS) {
    if ((counts.get(name) ?? 0) > 1) {
      problems.push(problem("error", `${name} appears more than once.`));
    }
  }

  const contacts: string[] = [];
  for (const f of parsed.fields) {
    if (!URI_FIELDS.has(f.name)) continue;
    const uri = parseUri(f.value);
    if (uri === undefined) {
      problems.push(problem("error", `${f.name} on line ${String(f.line)} is not a URI.`));
      continue;
    }
    if (uri.protocol === "http:") {
      problems.push(problem("error", `${f.name} on line ${String(f.line)} must use https://.`));
      continue;
    }
    if (f.name === "contact") contacts.push(f.value);
  }
  if (contacts.length === 0) {
    problems.push(problem("error", "No valid Contact field (required)."));
  }

  const expiresField = parsed.fields.find((f) => f.name === "expires");
  const expires = expiresField === undefined ? undefined : parseExpires(expiresField.value);
  if (expiresField === undefined) {
    problems.push(problem("error", "No Expires field (required)."));
  } else if (expires === undefined) {
    problems.push(problem("error", "Expires is not an RFC 3339 date-time."));
  } else if (expires.getTime() <= now.getTime()) {
    problems.push(
      problem("error", `Expired on ${expires.toISOString().slice(0, 10)}; treat as stale.`),
    );
  } else if (expires.getTime() - now.getTime() > MAX_RECOMMENDED_LIFETIME_MS) {
    problems.push(problem("warning", "Expires is more than a year away (keep it under one)."));
  }

  return { contacts, expires, problems };
}

function validateServing(obs: Extract<WellKnownObservation, { kind: "found" }>): {
  problems: SecurityTxtProblem[];
} {
  const problems: SecurityTxtProblem[] = [];
  const finalUrl = new URL(obs.finalUrl);
  if (finalUrl.protocol !== "https:") {
    problems.push(problem("error", "Served over plain HTTP (must be HTTPS)."));
  }
  if (new URL(obs.url).host !== finalUrl.host) {
    problems.push(problem("warning", `Redirects to another host (${finalUrl.host}).`));
  }
  if (obs.mediaType !== "text/plain") {
    problems.push(
      problem("warning", `Content-Type is ${obs.mediaType || "missing"}, not text/plain.`),
    );
  }
  if (obs.path === SECURITY_TXT_LEGACY_PATH) {
    problems.push(problem("warning", `Only found at the legacy path; serve ${SECURITY_TXT_PATH}.`));
  }
  if (obs.truncated) {
    problems.push(problem("error", `Larger than ${String(SECURITY_TXT_MAX_BYTES)} bytes.`));
  }
  return { problems };
}

function canonicalProblem(parsed: ParsedSecurityTxt, finalUrl: string): SecurityTxtProblem[] {
  const canonical = parsed.fields.filter((f) => f.name === "canonical").map((f) => f.value);
  if (canonical.length === 0) {
    return parsed.signed ? [problem("warning", "Signed but has no Canonical field (§2.5.2).")] : [];
  }
  return canonical.some((value) => parseUri(value)?.href === finalUrl)
    ? []
    : [problem("error", "Canonical does not list the URL it was served from.")];
}

/**
 * Grades a security.txt observation (RFC 9116):
 * - pass (10): HTTPS, text/plain, Contact and a future Expires, nothing wrong;
 * - warn (7): valid but with recommendations (legacy path, long Expires...);
 * - fail (3): present but invalid (no Contact/Expires, expired, http...);
 * - warn (0): not published;
 * - info: couldn't be fetched (network error), unscored.
 */
export function checkSecurityTxt(obs: SecurityTxtObservation, now: Date = new Date()): Finding {
  const base = { check: SECURITY_TXT_CHECK, weight: SECURITY_TXT_WEIGHT };
  if (obs.kind === "error") {
    return makeFinding({
      check: SECURITY_TXT_CHECK,
      status: Status.Info,
      detail: `Could not be fetched (${obs.code}).`,
    });
  }
  if (obs.kind === "missing") {
    return makeFinding({
      ...base,
      status: Status.Warn,
      score: 0,
      detail: `No security.txt (${obs.reason}).`,
      recommendation:
        `Publish ${SECURITY_TXT_PATH} (RFC 9116) with at least Contact and Expires, ` +
        "so researchers know where to report vulnerabilities.",
    });
  }

  const parsed = parseSecurityTxt(obs.text);
  const fields = validateFields(parsed, now);
  const problems = [
    ...validateServing(obs).problems,
    ...fields.problems,
    ...canonicalProblem(parsed, obs.finalUrl),
  ];
  const errors = problems.filter((p) => p.level === "error");
  const warnings = problems.filter((p) => p.level === "warning");
  const summary = [
    `${String(fields.contacts.length)} contact(s)`,
    fields.expires ? `expires ${fields.expires.toISOString().slice(0, 10)}` : "no valid expiry",
    parsed.signed ? "PGP-signed (signature not verified)" : "unsigned",
  ].join(", ");

  if (errors.length > 0) {
    return makeFinding({
      ...base,
      status: Status.Fail,
      score: 3,
      detail: `Invalid security.txt (${summary}): ${errors.map((p) => p.message).join(" ")}`,
      recommendation: [...errors, ...warnings].map((p) => p.message).join(" "),
    });
  }
  if (warnings.length > 0) {
    return makeFinding({
      ...base,
      status: Status.Warn,
      score: 7,
      detail: `security.txt present (${summary}).`,
      recommendation: warnings.map((p) => p.message).join(" "),
    });
  }
  return makeFinding({
    ...base,
    status: Status.Pass,
    score: SECURITY_TXT_WEIGHT,
    detail: `Valid security.txt (${summary}).`,
  });
}
