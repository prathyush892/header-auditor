/** Unit tests for the pure TLS checks: fixtures only, no sockets. */
import { describe, expect, it } from "vitest";
import {
  analyzeTls,
  buildTlsReport,
  certificateMatchesHost,
  checkCertificateHostname,
  checkCertificateKey,
  checkCertificateTrust,
  checkCertificateValidity,
  checkCipher,
  checkLegacyProtocols,
  checkTlsProtocol,
  classifyCipher,
  type CertificateInfo,
  type TlsSnapshot,
} from "../src/index.js";

const NOW = new Date("2026-06-01T00:00:00Z");
const DAY = 86_400_000;

function cert(overrides: Partial<CertificateInfo> = {}): CertificateInfo {
  return {
    subjectCommonName: "app.test",
    subjectAltName: "DNS:app.test, DNS:*.app.test",
    issuerCommonName: "Test Issuing CA",
    issuerOrganization: "Test Org",
    validFrom: new Date(NOW.getTime() - 30 * DAY),
    validTo: new Date(NOW.getTime() + 200 * DAY),
    keyType: "EC",
    keyBits: 256,
    selfIssued: false,
    fingerprint256: "AA:BB",
    ...overrides,
  };
}

function snapshot(overrides: Partial<TlsSnapshot> = {}): TlsSnapshot {
  return {
    hostname: "app.test",
    port: 443,
    protocol: "TLSv1.3",
    cipher: { name: "TLS_AES_128_GCM_SHA256", standardName: "TLS_AES_128_GCM_SHA256" },
    certificate: cert(),
    authorized: true,
    authorizationError: undefined,
    legacy: { TLSv1: "rejected", "TLSv1.1": "rejected" },
    ...overrides,
  };
}

describe("checkTlsProtocol", () => {
  it.each(["TLSv1.3", "TLSv1.2"])("passes %s", (p) => {
    const f = checkTlsProtocol(p);
    expect(f.status).toBe("pass");
    expect(f.score).toBe(f.weight);
  });

  it("suggests TLS 1.3 when only 1.2 is negotiated", () => {
    expect(checkTlsProtocol("TLSv1.2").recommendation).toMatch(/TLS 1\.3/);
    expect(checkTlsProtocol("TLSv1.3").recommendation).toBe("");
  });

  it.each(["TLSv1.1", "TLSv1", "SSLv3", "unknown"])("fails %s", (p) => {
    const f = checkTlsProtocol(p);
    expect(f.status).toBe("fail");
    expect(f.score).toBe(0);
  });
});

describe("checkLegacyProtocols", () => {
  it("passes when both legacy versions are refused", () => {
    expect(checkLegacyProtocols({ TLSv1: "rejected", "TLSv1.1": "rejected" }).status).toBe("pass");
  });

  it("fails and names every accepted version", () => {
    const f = checkLegacyProtocols({ TLSv1: "accepted", "TLSv1.1": "accepted" });
    expect(f.status).toBe("fail");
    expect(f.detail).toContain("TLSv1 and TLSv1.1");
  });

  it("fails if one is accepted even when the other is untested", () => {
    expect(checkLegacyProtocols({ TLSv1: "untested", "TLSv1.1": "accepted" }).status).toBe("fail");
  });

  it("is informational (weight 0) when nothing could be tested", () => {
    const f = checkLegacyProtocols({ TLSv1: "untested", "TLSv1.1": "untested" });
    expect(f.status).toBe("info");
    expect(f.weight).toBe(0);
  });

  it("passes but notes partially untested results", () => {
    const f = checkLegacyProtocols({ TLSv1: "untested", "TLSv1.1": "rejected" });
    expect(f.status).toBe("pass");
    expect(f.detail).toContain("could not be tested");
  });
});

describe("classifyCipher / checkCipher", () => {
  it.each([
    ["TLS_AES_256_GCM_SHA384", "TLS_AES_256_GCM_SHA384", "strong"],
    ["TLS_CHACHA20_POLY1305_SHA256", "TLS_CHACHA20_POLY1305_SHA256", "strong"],
    ["ECDHE-RSA-AES128-GCM-SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "strong"],
    ["ECDHE-ECDSA-CHACHA20-POLY1305", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "strong"],
    ["DHE-RSA-AES256-GCM-SHA384", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "strong"],
    ["ECDHE-RSA-AES256-SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "cbc"],
    ["AES128-GCM-SHA256", "TLS_RSA_WITH_AES_128_GCM_SHA256", "no-forward-secrecy"],
    ["AES128-SHA", "TLS_RSA_WITH_AES_128_CBC_SHA", "no-forward-secrecy"],
    ["DES-CBC3-SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "insecure"],
    ["RC4-SHA", "TLS_RSA_WITH_RC4_128_SHA", "insecure"],
    ["EXP-RC4-MD5", "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "insecure"],
    ["NULL-SHA256", "TLS_RSA_WITH_NULL_SHA256", "insecure"],
    ["ADH-AES128-GCM-SHA256", "TLS_DH_anon_WITH_AES_128_GCM_SHA256", "insecure"],
    ["AECDH-AES128-SHA", "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", "insecure"],
  ] as const)("%s → %s", (name, standardName, expected) => {
    expect(classifyCipher({ name, standardName })).toBe(expected);
  });

  it("scores each class", () => {
    const score = (name: string, standardName: string): [string, number] => {
      const f = checkCipher({ name, standardName });
      return [f.status, f.score];
    };
    expect(score("TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256")).toEqual(["pass", 15]);
    expect(score("ECDHE-RSA-AES256-SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA")).toEqual([
      "warn",
      10,
    ]);
    expect(score("AES128-SHA", "TLS_RSA_WITH_AES_128_CBC_SHA")).toEqual(["warn", 5]);
    expect(score("RC4-SHA", "TLS_RSA_WITH_RC4_128_SHA")).toEqual(["fail", 0]);
  });
});

describe("checkCertificateValidity", () => {
  const at = (days: number): CertificateInfo =>
    cert({ validTo: new Date(NOW.getTime() + days * DAY) });

  it("passes with plenty of time left", () => {
    const f = checkCertificateValidity(at(200), { now: NOW });
    expect(f.status).toBe("pass");
    expect(f.detail).toContain("200 days left");
  });

  it("warns inside the warning window", () => {
    const f = checkCertificateValidity(at(20), { now: NOW });
    expect([f.status, f.score]).toEqual(["warn", 12]);
  });

  it("fails (partial credit) inside the critical window", () => {
    const f = checkCertificateValidity(at(3), { now: NOW });
    expect([f.status, f.score]).toEqual(["fail", 5]);
  });

  it("fails with zero when expired", () => {
    const f = checkCertificateValidity(at(-1), { now: NOW });
    expect([f.status, f.score]).toEqual(["fail", 0]);
    expect(f.detail).toMatch(/expired on 2026-05-31/);
  });

  it("fails when not yet valid", () => {
    const f = checkCertificateValidity(cert({ validFrom: new Date(NOW.getTime() + DAY) }), {
      now: NOW,
    });
    expect(f.status).toBe("fail");
    expect(f.detail).toMatch(/not valid until/);
  });

  it("honours custom thresholds", () => {
    expect(checkCertificateValidity(at(40), { now: NOW, expiryWarnDays: 60 }).status).toBe("warn");
    expect(
      checkCertificateValidity(at(20), { now: NOW, expiryWarnDays: 10, expiryCriticalDays: 5 })
        .status,
    ).toBe("pass");
  });

  it.each([
    [{ expiryWarnDays: -1 }],
    [{ expiryWarnDays: 1.5 }],
    [{ expiryCriticalDays: 4000 }],
    [{ expiryWarnDays: 5, expiryCriticalDays: 10 }],
    [{ now: new Date("nope") }],
  ])("rejects bad options %j", (opts) => {
    expect(() => checkCertificateValidity(cert(), opts)).toThrow(RangeError);
  });

  it("fails when there is no certificate", () => {
    expect(checkCertificateValidity(undefined).status).toBe("fail");
  });
});

describe("certificateMatchesHost / checkCertificateHostname", () => {
  it("matches exact and single-label wildcard SANs", () => {
    expect(certificateMatchesHost("app.test", cert())).toBe(true);
    expect(certificateMatchesHost("www.app.test", cert())).toBe(true);
  });

  it("does not let a wildcard span two labels or match the apex of another name", () => {
    expect(certificateMatchesHost("a.b.app.test", cert())).toBe(false);
    expect(certificateMatchesHost("evil-app.test", cert())).toBe(false);
  });

  it("ignores the CN when SANs are present (RFC 6125)", () => {
    const c = cert({ subjectCommonName: "other.test", subjectAltName: "DNS:app.test" });
    expect(certificateMatchesHost("other.test", c)).toBe(false);
  });

  it("matches IP addresses only against IP SANs", () => {
    const c = cert({ subjectAltName: "DNS:app.test, IP Address:127.0.0.1" });
    expect(certificateMatchesHost("127.0.0.1", c)).toBe(true);
    expect(certificateMatchesHost("127.0.0.2", c)).toBe(false);
  });

  it("reports the names the certificate does cover", () => {
    const f = checkCertificateHostname("wrong.test", cert());
    expect(f.status).toBe("fail");
    expect(f.detail).toContain("DNS:app.test");
    expect(f.recommendation).toContain("wrong.test");
  });

  it("passes on a match", () => {
    expect(checkCertificateHostname("app.test", cert()).status).toBe("pass");
  });
});

describe("checkCertificateTrust", () => {
  it("passes an authorized chain and names the issuer", () => {
    const f = checkCertificateTrust(snapshot());
    expect(f.status).toBe("pass");
    expect(f.detail).toContain("Test Org");
  });

  it.each(["DEPTH_ZERO_SELF_SIGNED_CERT", "SELF_SIGNED_CERT_IN_CHAIN"])(
    "flags %s as self-signed",
    (code) => {
      const f = checkCertificateTrust(snapshot({ authorized: false, authorizationError: code }));
      expect(f.status).toBe("fail");
      expect(f.detail).toMatch(/self-signed/);
    },
  );

  it("flags an untrusted issuer", () => {
    const f = checkCertificateTrust(
      snapshot({ authorized: false, authorizationError: "UNABLE_TO_VERIFY_LEAF_SIGNATURE" }),
    );
    expect(f.status).toBe("fail");
    expect(f.recommendation).toMatch(/intermediate/);
  });

  it("gives partial credit when only the date blocked verification", () => {
    const f = checkCertificateTrust(
      snapshot({ authorized: false, authorizationError: "CERT_HAS_EXPIRED" }),
    );
    expect([f.status, f.score]).toEqual(["warn", 8]);
  });

  it("fails without a certificate", () => {
    expect(checkCertificateTrust(snapshot({ certificate: undefined })).status).toBe("fail");
  });
});

describe("checkCertificateKey", () => {
  it.each([
    ["RSA", 2048, "pass"],
    ["RSA", 4096, "pass"],
    ["RSA", 1024, "fail"],
    ["EC", 256, "pass"],
    ["EC", 384, "pass"],
    ["EC", 160, "fail"],
  ] as const)("%s %d → %s", (keyType, keyBits, status) => {
    expect(checkCertificateKey(cert({ keyType, keyBits })).status).toBe(status);
  });

  it("is informational when the key is unknown", () => {
    const f = checkCertificateKey(cert({ keyType: "unknown", keyBits: undefined }));
    expect([f.status, f.weight]).toEqual(["info", 0]);
  });
});

describe("analyzeTls / buildTlsReport", () => {
  it("grades a modern setup A with full marks", () => {
    const report = buildTlsReport(snapshot(), { now: NOW });
    expect(report.findings.map((f) => f.check)).toEqual([
      "TLS protocol",
      "Legacy TLS versions",
      "Cipher suite",
      "Certificate validity",
      "Certificate hostname",
      "Certificate trust",
      "Certificate key",
    ]);
    expect(report.score).toBe(100);
    expect(report.grade).toBe("A");
    expect(report.gradeCappedBy).toEqual([]);
    expect(report.host).toBe("app.test");
    expect(Object.isFrozen(report)).toBe(true);
  });

  it("grades a self-signed, wrong-host, legacy setup F", () => {
    const report = buildTlsReport(
      snapshot({
        hostname: "other.test",
        authorized: false,
        authorizationError: "DEPTH_ZERO_SELF_SIGNED_CERT",
        legacy: { TLSv1: "accepted", "TLSv1.1": "accepted" },
        certificate: cert({ selfIssued: true }),
      }),
      { now: NOW },
    );
    expect(report.grade).toBe("F");
    expect(report.gradeCappedBy).toEqual(["Certificate hostname", "Certificate trust"]);
    expect(report.score).toBeGreaterThan(40); // the points alone would have said "D"
  });

  it("caps an otherwise perfect setup at F when the certificate has expired", () => {
    const expired = cert({ validTo: new Date(NOW.getTime() - DAY) });
    const report = buildTlsReport(snapshot({ certificate: expired }), { now: NOW });
    expect(report.score).toBeGreaterThanOrEqual(75);
    expect(report.grade).toBe("F");
    expect(report.gradeCappedBy).toEqual(["Certificate validity"]);
  });

  it("does not cap for partial-credit failures (expiring within the critical window)", () => {
    const soon = cert({ validTo: new Date(NOW.getTime() + 3 * DAY) });
    const report = buildTlsReport(snapshot({ certificate: soon }), { now: NOW });
    expect(report.gradeCappedBy).toEqual([]);
    expect(report.grade).not.toBe("F");
  });

  it("keeps the score/weight invariant on every finding", () => {
    for (const f of analyzeTls(snapshot({ protocol: "TLSv1" }), { now: NOW })) {
      expect(f.score).toBeGreaterThanOrEqual(0);
      expect(f.score).toBeLessThanOrEqual(f.weight);
    }
  });

  it("rejects bad options up front", () => {
    expect(() => analyzeTls(snapshot(), { expiryWarnDays: -5 })).toThrow(RangeError);
  });
});
