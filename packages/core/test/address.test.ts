import { describe, expect, it } from "vitest";
import {
  createGuardedLookup,
  embeddedIpv4,
  isAddressAllowed,
  isPrivateAddress,
  normalizeAddress,
  parseAllowList,
  ScanError,
  validateTarget,
  type AddressPolicy,
  type LookupOutcome,
  type Resolver,
} from "../src/index.js";

const strict: AddressPolicy = { allowPrivate: false, allowList: parseAllowList([]) };

describe("isPrivateAddress", () => {
  it.each([
    "127.0.0.1",
    "127.255.255.254",
    "10.1.2.3",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "169.254.169.254", // cloud metadata
    "100.64.0.1",
    "0.0.0.0",
    "255.255.255.255",
    "224.0.0.1",
    "198.18.0.1",
    "192.0.2.10",
    "::",
    "::1",
    "[::1]",
    "0:0:0:0:0:0:0:1",
    "fe80::1",
    "fc00::1",
    "fd12:3456::1",
    "ff02::1",
    "2001:db8::1",
    "::ffff:127.0.0.1", // IPv4-mapped loopback
    "::ffff:7f00:1", // same, hex form
    "::ffff:169.254.169.254",
    "64:ff9b::a00:1", // NAT64 of 10.0.0.1
    "2002:7f00:1::", // 6to4 of 127.0.0.1
    "2002:c0a8:101::1", // 6to4 of 192.168.1.1
  ])("blocks %s", (address) => {
    expect(isPrivateAddress(address)).toBe(true);
  });

  it.each([
    "8.8.8.8",
    "1.1.1.1",
    "11.0.0.0",
    "172.15.255.255",
    "172.32.0.0",
    "100.63.255.255",
    "192.169.0.1",
    "2606:4700:4700::1111",
    "::ffff:8.8.8.8",
    "64:ff9b::808:808", // NAT64 of 8.8.8.8
    "2002:808:808::1", // 6to4 of 8.8.8.8
  ])("allows public %s", (address) => {
    expect(isPrivateAddress(address)).toBe(false);
  });

  it.each(["", "localhost", "not-an-ip", "999.1.1.1", "1.2.3", "::g"])(
    "fails closed on non-IP input %j",
    (input) => {
      expect(isPrivateAddress(input)).toBe(true);
    },
  );
});

describe("normalizeAddress / embeddedIpv4", () => {
  it("normalizes IPv6 and strips brackets", () => {
    expect(normalizeAddress("[0:0:0:0:0:0:0:1]")).toEqual({ address: "::1", family: 6 });
    expect(normalizeAddress("::FFFF:127.0.0.1")).toEqual({ address: "::ffff:7f00:1", family: 6 });
    expect(normalizeAddress("10.0.0.1")).toEqual({ address: "10.0.0.1", family: 4 });
    expect(normalizeAddress("example.com")).toBeUndefined();
  });

  it("extracts embedded IPv4 only from mapped, NAT64 and 6to4 forms", () => {
    expect(embeddedIpv4("::ffff:7f00:1")).toBe("127.0.0.1");
    expect(embeddedIpv4("64:ff9b::a9fe:a9fe")).toBe("169.254.169.254");
    expect(embeddedIpv4("2002:a00:1::")).toBe("10.0.0.1");
    expect(embeddedIpv4("2606:4700::1111")).toBeUndefined();
    expect(embeddedIpv4("::1")).toBeUndefined();
  });
});

describe("parseAllowList / isAddressAllowed", () => {
  it("lets listed addresses and ranges through a strict policy", () => {
    const policy: AddressPolicy = {
      allowPrivate: false,
      allowList: parseAllowList(["127.0.0.1", "192.168.10.0/24", " ::1 "]),
    };
    expect(isAddressAllowed("127.0.0.1", policy)).toBe(true);
    expect(isAddressAllowed("127.0.0.2", policy)).toBe(false);
    expect(isAddressAllowed("192.168.10.200", policy)).toBe(true);
    expect(isAddressAllowed("192.168.11.1", policy)).toBe(false);
    expect(isAddressAllowed("::1", policy)).toBe(true);
    expect(isAddressAllowed("8.8.8.8", policy)).toBe(true);
  });

  it("allowPrivate opens everything; strict blocks private and junk", () => {
    expect(isAddressAllowed("10.0.0.1", { ...strict, allowPrivate: true })).toBe(true);
    expect(isAddressAllowed("10.0.0.1", strict)).toBe(false);
    expect(isAddressAllowed("nonsense", strict)).toBe(false);
  });

  it.each([
    "",
    "localhost",
    "10.0.0.0/33",
    "::/129",
    "10.0.0.0/abc",
    "10.0.0.0/8/8",
    "10.0.0.0/-1",
  ])("rejects invalid entry %j", (entry) => {
    expect(() => parseAllowList([entry])).toThrow(TypeError);
  });
});

describe("validateTarget", () => {
  const codeOf = (raw: string, policy = strict): string | undefined => {
    try {
      validateTarget(raw, policy);
      return undefined;
    } catch (err) {
      return err instanceof ScanError ? err.code : "not-a-scan-error";
    }
  };

  it.each([
    ["http://127.0.0.1/", "BLOCKED_ADDRESS"],
    ["http://2130706433/", "BLOCKED_ADDRESS"], // decimal 127.0.0.1
    ["http://0x7f.1/", "BLOCKED_ADDRESS"], // hex/short form
    ["http://[::ffff:127.0.0.1]/", "BLOCKED_ADDRESS"],
    ["http://[::1]:8080/", "BLOCKED_ADDRESS"],
    ["http://169.254.169.254/latest/meta-data/", "BLOCKED_ADDRESS"],
    ["ftp://example.com/", "BLOCKED_SCHEME"],
    ["file:///etc/passwd", "BLOCKED_SCHEME"],
    ["javascript:alert(1)", "BLOCKED_SCHEME"],
    ["gopher://127.0.0.1:6379/_", "BLOCKED_SCHEME"],
    ["not a url", "INVALID_URL"],
    ["/relative/path", "INVALID_URL"],
    ["http://user:pass@example.com/", "INVALID_URL"],
    [`http://example.com/${"a".repeat(2100)}`, "INVALID_URL"],
  ])("%s → %s", (raw, code) => {
    expect(codeOf(raw)).toBe(code);
  });

  it("accepts public hostnames and IPs (DNS is checked later, at connect)", () => {
    expect(codeOf("https://example.com/path?q=1")).toBeUndefined();
    expect(codeOf("http://8.8.8.8/")).toBeUndefined();
  });

  it("does not leak credentials in the error URL and strips fragments", () => {
    try {
      validateTarget("http://admin:hunter2@example.com/x", strict);
      expect.unreachable();
    } catch (err) {
      expect((err as ScanError).url).toBe("http://example.com/x");
      expect((err as ScanError).message).not.toContain("hunter2");
    }
    expect(validateTarget("https://example.com/a#frag", strict).href).toBe("https://example.com/a");
  });
});

describe("createGuardedLookup", () => {
  const run = (
    resolver: Resolver,
    options: { all?: boolean; family?: number },
    policy = strict,
  ): Promise<{ err: Error | null; result: unknown; family?: number; outcome: LookupOutcome }> => {
    const outcome: LookupOutcome = {};
    const lookup = createGuardedLookup(resolver, policy, outcome);
    return new Promise((resolve) => {
      lookup("host.test", options, (err, result, family) => {
        resolve({ err, result, ...(family === undefined ? {} : { family }), outcome });
      });
    });
  };

  const fixture =
    (...addresses: [string, 4 | 6][]): Resolver =>
    () =>
      Promise.resolve(addresses.map(([address, family]) => ({ address, family })));

  it("returns the first address, or all of them when asked", async () => {
    const resolver = fixture(["8.8.8.8", 4], ["2606:4700::1", 6]);
    const single = await run(resolver, {});
    expect(single.err).toBeNull();
    expect(single.result).toBe("8.8.8.8");
    expect(single.family).toBe(4);
    const all = await run(resolver, { all: true });
    expect(all.result).toEqual([
      { address: "8.8.8.8", family: 4 },
      { address: "2606:4700::1", family: 6 },
    ]);
    const v6 = await run(resolver, { family: 6 });
    expect(v6.result).toBe("2606:4700::1");
  });

  it("rejects the whole host if any answer is private (rebinding / mixed records)", async () => {
    const { err, outcome } = await run(fixture(["8.8.8.8", 4], ["10.0.0.7", 4]), { all: true });
    expect(err?.name).toBe("BlockedAddressError");
    expect(outcome.blocked).toEqual({ hostname: "host.test", address: "10.0.0.7" });
  });

  it("reports empty answers and resolver failures as DNS errors", async () => {
    const empty = await run(fixture(), {});
    expect(empty.err).toBeInstanceOf(Error);
    expect(empty.outcome.dnsError).toBeDefined();
    const failing = await run(() => Promise.reject(new Error("ENOTFOUND host.test")), {});
    expect(failing.err?.message).toContain("ENOTFOUND");
    expect(failing.outcome.dnsError).toBeDefined();
  });
});
