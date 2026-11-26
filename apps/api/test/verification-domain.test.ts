/**
 * The verification rules on their own: which record name, which value, and
 * how a TXT answer is judged. Then the real c-ares resolver against a DNS
 * server on 127.0.0.1, to prove the production wiring queries the right
 * name and maps failures correctly.
 */
import { DnsLookupError, type DnsResolver } from "@header-auditor/core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { loadConfig } from "../src/config.js";
import {
  createDomainVerifier,
  createVerifierFromConfig,
  evaluateTxtRecords,
  MAX_TXT_RECORDS_EXAMINED,
  verificationRecord,
  verificationRecordOrNull,
  VerificationUnsupportedError,
} from "../src/verification/index.js";
import { fixtureResolver, startDnsServer } from "./helpers/dns.js";

const TOKEN = "a".repeat(64);
const OTHER = "b".repeat(64);
const VALUE = `header-auditor-verification=${TOKEN}`;
const NAME = "_header-auditor-challenge.www.example.com";

describe("verificationRecord", () => {
  it("names an underscore record under the exact hostname", () => {
    expect(verificationRecord("https://www.example.com", TOKEN)).toEqual({
      name: NAME,
      type: "TXT",
      value: VALUE,
    });
  });

  it("ignores port and path, and normalises case and IDNs", () => {
    expect(verificationRecord("https://WWW.Example.COM:8443/shop", TOKEN).name).toBe(NAME);
    expect(verificationRecord("https://bücher.example", TOKEN).name).toBe(
      "_header-auditor-challenge.xn--bcher-kva.example",
    );
  });

  it.each([
    "https://127.0.0.1",
    "https://[::1]:8443",
    "http://localhost:3000",
    "https://intranet",
    "not a url",
  ])("refuses %s, which has no DNS name to check", (url) => {
    expect(() => verificationRecord(url, TOKEN)).toThrow(VerificationUnsupportedError);
    expect(verificationRecordOrNull(url, TOKEN)).toBeNull();
  });

  it.each(["", "A".repeat(64), "a".repeat(63), `${"a".repeat(63)}\n`])(
    "rejects a malformed token %j",
    (token) => {
      expect(() => verificationRecord("https://example.com", token)).toThrow(RangeError);
      expect(verificationRecordOrNull("https://example.com", token)).toBeNull();
    },
  );
});

describe("evaluateTxtRecords", () => {
  const record = verificationRecord("https://www.example.com", TOKEN);

  it.each([
    [[VALUE], "VERIFIED"],
    [[`  ${VALUE}\t`], "VERIFIED"],
    [["v=spf1 -all", `header-auditor-verification=${OTHER}`, VALUE], "VERIFIED"],
    [[], "RECORD_MISSING"],
    [["v=spf1 -all", "google-site-verification=xyz"], "RECORD_MISSING"],
    [[`header-auditor-verification=${OTHER}`], "TOKEN_MISMATCH"],
    [[`HEADER-AUDITOR-VERIFICATION=${TOKEN.toUpperCase()}`], "TOKEN_MISMATCH"],
    [[`${VALUE}x`], "TOKEN_MISMATCH"],
    [[`x${VALUE}`], "RECORD_MISSING"],
  ] as const)("%j → %s", (records, status) => {
    expect(evaluateTxtRecords(records, record)).toEqual({ status });
  });

  it(`looks at no more than ${String(MAX_TXT_RECORDS_EXAMINED)} records`, () => {
    const filler = Array.from({ length: MAX_TXT_RECORDS_EXAMINED }, (_, i) => `noise ${String(i)}`);
    expect(evaluateTxtRecords([...filler, VALUE], record)).toEqual({ status: "RECORD_MISSING" });
    expect(evaluateTxtRecords([...filler.slice(1), VALUE], record)).toEqual({
      status: "VERIFIED",
    });
  });
});

describe("createDomainVerifier", () => {
  it("queries only the challenge name and reports the record with the outcome", async () => {
    const resolver = fixtureResolver({ [NAME]: { txt: [VALUE] } });
    const result = await createDomainVerifier(resolver).verify("https://www.example.com", TOKEN);
    expect(result).toEqual({
      status: "VERIFIED",
      record: { name: NAME, type: "TXT", value: VALUE },
    });
    expect(resolver.queries).toEqual([`TXT ${NAME}`]);
  });

  it("does not accept a record at the parent or the bare hostname", async () => {
    const resolver = fixtureResolver({
      "www.example.com": { txt: [VALUE] },
      "_header-auditor-challenge.example.com": { txt: [VALUE] },
    });
    const result = await createDomainVerifier(resolver).verify("https://www.example.com", TOKEN);
    expect(result.status).toBe("RECORD_MISSING");
  });

  it("turns a failed lookup into DNS_ERROR, not a verdict", async () => {
    const resolver = fixtureResolver({ [NAME]: { fail: "SERVFAIL" } });
    const result = await createDomainVerifier(resolver).verify("https://www.example.com", TOKEN);
    expect(result).toMatchObject({ status: "DNS_ERROR", code: "SERVFAIL" });
  });

  it("lets unexpected errors through", async () => {
    const resolver: DnsResolver = {
      txt: () => Promise.reject(new Error("bug")),
      caa: () => Promise.resolve([]),
    };
    await expect(
      createDomainVerifier(resolver).verify("https://www.example.com", TOKEN),
    ).rejects.toThrow("bug");
  });

  it("refuses IP-literal sites before any query", async () => {
    const resolver = fixtureResolver({});
    await expect(
      createDomainVerifier(resolver).verify("https://192.0.2.1", TOKEN),
    ).rejects.toBeInstanceOf(VerificationUnsupportedError);
    expect(resolver.queries).toEqual([]);
  });

  it("keeps DnsLookupError as the one error type it maps", () => {
    // Guards the import: the core class is what the fixture throws.
    expect(new DnsLookupError(NAME, "TXT", "TIMEOUT").code).toBe("TIMEOUT");
  });
});

describe("createVerifierFromConfig against a DNS server on 127.0.0.1", () => {
  let server: Awaited<ReturnType<typeof startDnsServer>>;

  beforeAll(async () => {
    server = await startDnsServer({
      [NAME]: { txt: [["v=spf1 -all"], ["header-auditor-verification=", TOKEN]] },
      "_header-auditor-challenge.wrong.example.com": {
        txt: [[`header-auditor-verification=${OTHER}`]],
      },
      "_header-auditor-challenge.broken.example.com": { rcode: "SERVFAIL" },
      "_header-auditor-challenge.slow.example.com": { drop: true },
    });
    expect(server.address.startsWith("127.0.0.1:")).toBe(true);
  });

  afterAll(async () => {
    await server.close();
  });

  function verifier() {
    const config = loadConfig({
      SITES_VERIFICATION_DNS_SERVERS: server.address,
      SITES_VERIFICATION_DNS_TIMEOUT_MS: "200",
    });
    return createVerifierFromConfig(config.sites.verification);
  }

  it.each([
    // The value is split over two character-strings; RFC 7208 §3.3 says join them.
    ["https://www.example.com", "VERIFIED"],
    ["https://wrong.example.com", "TOKEN_MISMATCH"],
    ["https://missing.example.com", "RECORD_MISSING"],
    ["https://broken.example.com", "DNS_ERROR"],
    ["https://slow.example.com", "DNS_ERROR"],
  ])("%s → %s", async (url, status) => {
    const result = await verifier().verify(url, TOKEN);
    expect(result.status).toBe(status);
  });
});
