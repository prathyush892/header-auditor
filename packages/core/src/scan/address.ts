/**
 * SSRF address policy: decides whether the scanner may open a connection to
 * an IP address.
 *
 * A hosted scanner takes URLs from users and fetches them from inside our own
 * network, so without this guard anyone could make it reach `127.0.0.1`, the
 * cloud metadata service on `169.254.169.254`, or a database on `10.x`. The
 * policy is a deny-list of every non-public range (IANA special-purpose
 * registries for IPv4 and IPv6), plus decoding of the IPv6 forms that embed an
 * IPv4 address, so `::ffff:127.0.0.1` or `64:ff9b::a00:1` can't smuggle a
 * private target past it.
 */
import { BlockList, isIP } from "node:net";

export type IpFamily = 4 | 6;

/** [network, prefix length] pairs that are never publicly routable. */
const BLOCKED_V4: readonly (readonly [string, number])[] = [
  ["0.0.0.0", 8], // "this network"; 0.0.0.0 reaches localhost on Linux
  ["10.0.0.0", 8], // RFC 1918 private
  ["100.64.0.0", 10], // carrier-grade NAT
  ["127.0.0.0", 8], // loopback
  ["169.254.0.0", 16], // link-local, incl. cloud metadata 169.254.169.254
  ["172.16.0.0", 12], // RFC 1918 private
  ["192.0.0.0", 24], // IETF protocol assignments
  ["192.0.2.0", 24], // TEST-NET-1
  ["192.88.99.0", 24], // deprecated 6to4 relay anycast
  ["192.168.0.0", 16], // RFC 1918 private
  ["198.18.0.0", 15], // benchmarking
  ["198.51.100.0", 24], // TEST-NET-2
  ["203.0.113.0", 24], // TEST-NET-3
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved + limited broadcast 255.255.255.255
];

const BLOCKED_V6: readonly (readonly [string, number])[] = [
  ["::", 128], // unspecified
  ["::1", 128], // loopback
  ["100::", 64], // discard-only
  ["64:ff9b:1::", 48], // local-use NAT64
  ["2001::", 23], // IETF protocol assignments (incl. Teredo 2001::/32)
  ["2001:db8::", 32], // documentation
  ["fc00::", 7], // unique local
  ["fe80::", 10], // link-local
  ["fec0::", 10], // deprecated site-local
  ["ff00::", 8], // multicast
];

function buildBlockList(): BlockList {
  const list = new BlockList();
  for (const [net, prefix] of BLOCKED_V4) list.addSubnet(net, prefix, "ipv4");
  for (const [net, prefix] of BLOCKED_V6) list.addSubnet(net, prefix, "ipv6");
  return list;
}

const BLOCKED = buildBlockList();

/**
 * Canonical text form of an IP address, or undefined if `input` isn't one.
 * Accepts bracketed IPv6 (`[::1]`, as in URL hostnames). IPv6 is lowercased
 * and compressed by the WHATWG URL parser, so `0:0:0:0:0:0:0:1` → `::1`.
 */
export function normalizeAddress(input: string): { address: string; family: IpFamily } | undefined {
  const bare = input.startsWith("[") && input.endsWith("]") ? input.slice(1, -1) : input;
  const family = isIP(bare);
  if (family === 4) return { address: bare, family };
  if (family !== 6) return undefined;
  const hostname = new URL(`http://[${bare}]/`).hostname;
  return { address: hostname.slice(1, -1), family };
}

/** The eight 16-bit groups of an IPv6 address in canonical (hex-only) form. */
function ipv6Groups(address: string): number[] {
  const [head = "", tail] = address.split("::");
  const parse = (part: string): number[] =>
    part === "" ? [] : part.split(":").map((g) => Number.parseInt(g, 16));
  const left = parse(head);
  const right = tail === undefined ? [] : parse(tail);
  const zeros = new Array<number>(8 - left.length - right.length).fill(0);
  return [...left, ...zeros, ...right];
}

function v4FromGroups(high: number, low: number): string {
  return [high >> 8, high & 0xff, low >> 8, low & 0xff].join(".");
}

/**
 * The IPv4 address embedded in an IPv4-mapped (`::ffff:a.b.c.d`), NAT64
 * (`64:ff9b::/96`) or 6to4 (`2002::/16`) IPv6 address, if any.
 */
export function embeddedIpv4(ipv6: string): string | undefined {
  const [g0 = 0, g1 = 0, g2 = 0, g3 = 0, g4 = 0, g5 = 0, g6 = 0, g7 = 0] = ipv6Groups(ipv6);
  const middleZero = g2 === 0 && g3 === 0 && g4 === 0;
  if (g0 === 0 && g1 === 0 && middleZero && g5 === 0xffff) return v4FromGroups(g6, g7);
  if (g0 === 0x64 && g1 === 0xff9b && middleZero && g5 === 0) return v4FromGroups(g6, g7);
  if (g0 === 0x2002) return v4FromGroups(g1, g2);
  return undefined;
}

/**
 * True when `address` is loopback, private, link-local, reserved or otherwise
 * not a public unicast address. Anything that isn't a valid IP is treated as
 * private, so a parsing surprise fails closed.
 */
export function isPrivateAddress(address: string): boolean {
  const normalized = normalizeAddress(address);
  if (!normalized) return true;
  if (normalized.family === 4) return BLOCKED.check(normalized.address, "ipv4");
  if (BLOCKED.check(normalized.address, "ipv6")) return true;
  const v4 = embeddedIpv4(normalized.address);
  return v4 !== undefined && BLOCKED.check(v4, "ipv4");
}

/**
 * An explicit allow-list of addresses or CIDR ranges (`"10.0.0.5"`,
 * `"192.168.1.0/24"`, `"::1"`) that are reachable even when private ranges
 * are blocked, e.g. one staging box on the LAN.
 *
 * @throws TypeError on an entry that isn't an IP address or valid CIDR.
 */
export function parseAllowList(entries: readonly string[]): BlockList {
  const list = new BlockList();
  for (const entry of entries) {
    const [ip = "", prefixText, extra] = entry.trim().split("/");
    const normalized = normalizeAddress(ip);
    if (!normalized || extra !== undefined) {
      throw new TypeError(`Invalid allow-list entry: ${JSON.stringify(entry)}`);
    }
    const type = normalized.family === 4 ? "ipv4" : "ipv6";
    if (prefixText === undefined) {
      list.addAddress(normalized.address, type);
      continue;
    }
    const prefix = Number(prefixText);
    const max = normalized.family === 4 ? 32 : 128;
    if (!/^\d{1,3}$/.test(prefixText) || prefix > max) {
      throw new TypeError(`Invalid prefix length in allow-list entry: ${JSON.stringify(entry)}`);
    }
    list.addSubnet(normalized.address, prefix, type);
  }
  return list;
}

export interface AddressPolicy {
  /** Permit every private/loopback/reserved address (local development only). */
  readonly allowPrivate: boolean;
  /** Specific addresses permitted even when `allowPrivate` is false. */
  readonly allowList: BlockList;
}

/** Whether the policy lets the scanner connect to `address`. */
export function isAddressAllowed(address: string, policy: AddressPolicy): boolean {
  if (policy.allowPrivate) return true;
  const normalized = normalizeAddress(address);
  if (!normalized) return false;
  if (policy.allowList.check(normalized.address, normalized.family === 4 ? "ipv4" : "ipv6")) {
    return true;
  }
  return !isPrivateAddress(normalized.address);
}
