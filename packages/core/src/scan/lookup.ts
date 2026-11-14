/**
 * DNS lookup that enforces the SSRF address policy *at connect time*.
 *
 * Checking a hostname's addresses before the request and then letting the
 * socket resolve it again is a time-of-check/time-of-use gap: a DNS-rebinding
 * server answers the first query with a public IP and the second with
 * 127.0.0.1. Plugging the check into the socket's own `lookup` means the
 * address that gets validated is the address that gets connected to.
 */
import { promises as dns, type LookupAddress } from "node:dns";
import type { LookupFunction } from "node:net";
import { isAddressAllowed, type AddressPolicy, type IpFamily } from "./address.js";

export interface ResolvedAddress {
  readonly address: string;
  readonly family: IpFamily;
}

/** Resolves a hostname to every address it has. Injectable so tests use fixtures. */
export type Resolver = (hostname: string) => Promise<readonly ResolvedAddress[]>;

export const systemResolver: Resolver = async (hostname) => {
  const results = await dns.lookup(hostname, { all: true, order: "verbatim" });
  return results.flatMap((r) =>
    r.family === 4 || r.family === 6 ? [{ address: r.address, family: r.family }] : [],
  );
};

/** What the guard saw, so the caller can turn a socket error into a precise ScanError. */
export interface LookupOutcome {
  blocked?: { hostname: string; address: string };
  dnsError?: unknown;
}

export class BlockedAddressError extends Error {
  override readonly name = "BlockedAddressError";
  readonly code = "ERR_SSRF_BLOCKED";
}

/**
 * Builds a `net.connect`-compatible lookup that resolves with `resolver` and
 * fails if *any* resolved address is disallowed. Rejecting the whole host (not
 * just filtering bad records) is deliberate: a name that mixes public and
 * private answers is either misconfigured or an attack.
 */
export function createGuardedLookup(
  resolver: Resolver,
  policy: AddressPolicy,
  outcome: LookupOutcome,
): LookupFunction {
  return (hostname, options, callback) => {
    resolver(hostname).then(
      (records) => {
        const wanted = options.family === 4 || options.family === 6 ? options.family : undefined;
        const candidates = records.filter((r) => wanted === undefined || r.family === wanted);
        const denied = records.find((r) => !isAddressAllowed(r.address, policy));
        if (denied) {
          outcome.blocked = { hostname, address: denied.address };
          callback(
            new BlockedAddressError(`Blocked address ${denied.address} for ${hostname}`),
            "",
          );
          return;
        }
        const first = candidates[0];
        if (!first) {
          const err = Object.assign(new Error(`No addresses found for ${hostname}`), {
            code: "ENOTFOUND",
          });
          outcome.dnsError = err;
          callback(err, "");
          return;
        }
        if (options.all) {
          const all: LookupAddress[] = candidates.map((r) => ({
            address: r.address,
            family: r.family,
          }));
          callback(null, all);
        } else {
          callback(null, first.address, first.family);
        }
      },
      (err: unknown) => {
        outcome.dnsError = err;
        callback(err instanceof Error ? err : new Error(String(err)), "");
      },
    );
  };
}
