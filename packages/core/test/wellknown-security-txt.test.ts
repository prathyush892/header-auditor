import { describe, expect, it } from "vitest";
import {
  checkSecurityTxt,
  parseExpires,
  parseSecurityTxt,
  SECURITY_TXT_LEGACY_PATH,
  SECURITY_TXT_PATH,
  SECURITY_TXT_WEIGHT,
  Status,
  type WellKnownObservation,
} from "../src/index.js";

const NOW = new Date("2026-11-18T12:00:00Z");
const URL_PRIMARY = `https://example.test${SECURITY_TXT_PATH}`;

function found(
  text: string,
  extra: Partial<Extract<WellKnownObservation, { kind: "found" }>> = {},
): WellKnownObservation {
  return {
    kind: "found",
    url: URL_PRIMARY,
    path: SECURITY_TXT_PATH,
    finalUrl: URL_PRIMARY,
    statusCode: 200,
    mediaType: "text/plain",
    text,
    truncated: false,
    redirects: [],
    ...extra,
  };
}

const GOOD = [
  "# Report security issues here",
  "Contact: mailto:security@example.test",
  "Contact: https://example.test/report",
  "Expires: 2027-06-30T23:59:59Z",
  "Preferred-Languages: en, fr",
  `Canonical: ${URL_PRIMARY}`,
  "Policy: https://example.test/disclosure",
].join("\n");

describe("parseSecurityTxt", () => {
  it("parses fields case-insensitively and skips comments and blank lines", () => {
    const parsed = parseSecurityTxt(
      "# hi\n\nCONTACT: mailto:a@example.test\r\nexpires:2027-01-01T00:00:00Z\n",
    );
    expect(parsed.fields.map((f) => [f.name, f.value, f.line])).toEqual([
      ["contact", "mailto:a@example.test", 3],
      ["expires", "2027-01-01T00:00:00Z", 4],
    ]);
    expect(parsed.problems).toEqual([]);
    expect(parsed.signed).toBe(false);
  });

  it("strips a byte-order mark", () => {
    expect(parseSecurityTxt("﻿Contact: mailto:a@example.test").fields[0]?.name).toBe("contact");
  });

  it("reports malformed lines, capped at three plus a count", () => {
    const parsed = parseSecurityTxt(
      ["no colon", ": empty name", "bad name: x", "a", "b", "Contact: mailto:a@example.test"].join(
        "\n",
      ),
    );
    expect(parsed.fields).toHaveLength(1);
    expect(parsed.problems.map((p) => p.message)).toEqual([
      'Line 1 is not a "Field: value" line.',
      'Line 2 is not a "Field: value" line.',
      'Line 3 is not a "Field: value" line.',
      "2 more malformed lines.",
    ]);
  });

  it("unwraps an OpenPGP cleartext-signed file and unescapes dash-escaped lines", () => {
    const text = [
      "-----BEGIN PGP SIGNED MESSAGE-----",
      "Hash: SHA256",
      "",
      "Contact: mailto:a@example.test",
      "- # dash-escaped comment",
      "-----BEGIN PGP SIGNATURE-----",
      "",
      "iQEzBAEBCAAdFiEEfixturefixturefixture",
      "-----END PGP SIGNATURE-----",
    ].join("\n");
    const parsed = parseSecurityTxt(text);
    expect(parsed.signed).toBe(true);
    expect(parsed.fields.map((f) => f.name)).toEqual(["contact"]);
    expect(parsed.problems).toEqual([]);
  });

  it("flags a signed header without a signature block", () => {
    const parsed = parseSecurityTxt(
      "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nContact: mailto:a@example.test\n",
    );
    expect(parsed.signed).toBe(false);
    expect(parsed.problems[0]?.message).toMatch(/no PGP signature/);
  });
});

describe("parseExpires", () => {
  it.each([
    ["2027-01-31T23:59:59Z", "2027-01-31T23:59:59.000Z"],
    ["2027-01-31t23:59:59z", "2027-01-31T23:59:59.000Z"],
    ["2027-01-31T23:59:59.123Z", "2027-01-31T23:59:59.123Z"],
    ["2027-01-31T20:00:00-05:00", "2027-02-01T01:00:00.000Z"],
  ])("accepts %s", (value, iso) => {
    expect(parseExpires(value)?.toISOString()).toBe(iso);
  });

  it.each([
    "2027-01-31",
    "2027-01-31 23:59:59Z",
    "2027-01-31T23:59:59",
    "2027-02-30T00:00:00Z",
    "2027-13-01T00:00:00Z",
    "2027-01-01T24:00:00Z",
    "2027-01-01T00:00:00.Z",
    "2027-01-01T00:00:00+5:00",
    "Tue, 01 Jan 2027 00:00:00 GMT",
    "",
  ])("rejects %j", (value) => {
    expect(parseExpires(value)).toBeUndefined();
  });
});

describe("checkSecurityTxt", () => {
  it("passes a valid, current file", () => {
    const f = checkSecurityTxt(found(GOOD), NOW);
    expect(f.status).toBe(Status.Pass);
    expect(f.score).toBe(SECURITY_TXT_WEIGHT);
    expect(f.detail).toContain("2 contact(s)");
    expect(f.detail).toContain("expires 2027-06-30");
  });

  it("warns (0) when the file is missing", () => {
    const f = checkSecurityTxt(
      {
        kind: "missing",
        url: URL_PRIMARY,
        path: SECURITY_TXT_PATH,
        statusCode: 404,
        reason: "HTTP 404",
      },
      NOW,
    );
    expect(f.status).toBe(Status.Warn);
    expect(f.score).toBe(0);
    expect(f.detail).toContain("HTTP 404");
    expect(f.recommendation).toContain("RFC 9116");
  });

  it("is unscored info when it couldn't be fetched", () => {
    const f = checkSecurityTxt(
      { kind: "error", url: URL_PRIMARY, path: SECURITY_TXT_PATH, code: "TIMEOUT" },
      NOW,
    );
    expect(f.status).toBe(Status.Info);
    expect(f.weight).toBe(0);
    expect(f.detail).toContain("TIMEOUT");
  });

  it.each([
    ["no Contact", "Expires: 2027-01-01T00:00:00Z", /No valid Contact/],
    ["no Expires", "Contact: mailto:a@example.test", /No Expires/],
    ["bad Expires", "Contact: mailto:a@example.test\nExpires: next year", /not an RFC 3339/],
    [
      "expired",
      "Contact: mailto:a@example.test\nExpires: 2026-01-01T00:00:00Z",
      /Expired on 2026-01-01/,
    ],
    [
      "two Expires",
      "Contact: mailto:a@example.test\nExpires: 2027-01-01T00:00:00Z\nExpires: 2027-02-01T00:00:00Z",
      /expires appears more than once/,
    ],
    [
      "http Contact",
      "Contact: http://example.test/report\nExpires: 2027-01-01T00:00:00Z",
      /must use https/,
    ],
    [
      "non-URI Contact",
      "Contact: security@example.test\nExpires: 2027-01-01T00:00:00Z",
      /not a URI/,
    ],
    [
      "wrong Canonical",
      "Contact: mailto:a@example.test\nExpires: 2027-01-01T00:00:00Z\nCanonical: https://other.test/.well-known/security.txt",
      /Canonical does not list/,
    ],
  ])("fails (3) with %s", (_name, text, message) => {
    const f = checkSecurityTxt(found(text), NOW);
    expect(f.status).toBe(Status.Fail);
    expect(f.score).toBe(3);
    expect(f.detail).toMatch(message);
  });

  it("fails when served over plain http", () => {
    const http = "http://example.test/.well-known/security.txt";
    const f = checkSecurityTxt(
      found(GOOD.replace(URL_PRIMARY, http), { url: http, finalUrl: http }),
      NOW,
    );
    expect(f.status).toBe(Status.Fail);
    expect(f.detail).toContain("plain HTTP");
  });

  it("fails when the body was truncated", () => {
    const f = checkSecurityTxt(found(GOOD, { truncated: true }), NOW);
    expect(f.status).toBe(Status.Fail);
    expect(f.detail).toContain("Larger than");
  });

  it.each([
    [
      "legacy path",
      found(GOOD.replace(`Canonical: ${URL_PRIMARY}\n`, ""), {
        path: SECURITY_TXT_LEGACY_PATH,
        url: "https://example.test/security.txt",
        finalUrl: "https://example.test/security.txt",
      }),
      /legacy path/,
    ],
    ["wrong media type", found(GOOD, { mediaType: "application/octet-stream" }), /not text\/plain/],
    ["missing media type", found(GOOD, { mediaType: "" }), /Content-Type is missing/],
    ["far-off Expires", found(GOOD.replace("2027-06-30", "2028-06-30")), /more than a year away/],
    [
      "cross-host redirect",
      found(GOOD.replace(URL_PRIMARY, "https://sec.example.test/security.txt"), {
        finalUrl: "https://sec.example.test/security.txt",
      }),
      /another host/,
    ],
  ])("warns (7) on %s", (_name, obs, message) => {
    const f = checkSecurityTxt(obs, NOW);
    expect(f.status).toBe(Status.Warn);
    expect(f.score).toBe(7);
    expect(f.recommendation).toMatch(message);
  });

  it("warns when a signed file has no Canonical", () => {
    const text = [
      "-----BEGIN PGP SIGNED MESSAGE-----",
      "Hash: SHA256",
      "",
      "Contact: mailto:a@example.test",
      "Expires: 2027-01-01T00:00:00Z",
      "-----BEGIN PGP SIGNATURE-----",
      "fixture",
      "-----END PGP SIGNATURE-----",
    ].join("\n");
    const f = checkSecurityTxt(found(text), NOW);
    expect(f.status).toBe(Status.Warn);
    expect(f.detail).toContain("PGP-signed (signature not verified)");
    expect(f.recommendation).toContain("Canonical");
  });

  it("matches Canonical after URL normalisation", () => {
    const text = GOOD.replace(
      `Canonical: ${URL_PRIMARY}`,
      "Canonical: HTTPS://EXAMPLE.TEST:443/.well-known/security.txt",
    );
    expect(checkSecurityTxt(found(text), NOW).status).toBe(Status.Pass);
  });

  it("ignores unknown fields", () => {
    expect(checkSecurityTxt(found(`${GOOD}\nX-Custom: anything`), NOW).status).toBe(Status.Pass);
  });

  it("uses the current time by default", () => {
    expect(
      checkSecurityTxt(found("Contact: mailto:a@example.test\nExpires: 2000-01-01T00:00:00Z"))
        .status,
    ).toBe(Status.Fail);
  });
});
