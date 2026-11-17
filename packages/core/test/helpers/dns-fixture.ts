/** In-memory DnsResolver for unit tests: a zone map plus a log of every query. */
import {
  DnsLookupError,
  type CaaRecord,
  type DnsErrorCode,
  type DnsResolver,
} from "../../src/index.js";

export interface FixtureName {
  txt?: string[];
  caa?: CaaRecord[];
  /** Every lookup of this name fails with this code. */
  fail?: DnsErrorCode;
}

export interface FixtureResolver extends DnsResolver {
  readonly queries: string[];
}

export function fixtureResolver(zone: Readonly<Record<string, FixtureName>>): FixtureResolver {
  const entries = new Map(Object.entries(zone));
  const queries: string[] = [];
  const lookup = <T>(
    rrtype: "TXT" | "CAA",
    name: string,
    pick: (n: FixtureName) => T[] | undefined,
  ) => {
    queries.push(`${rrtype} ${name}`);
    const entry = entries.get(name);
    if (entry?.fail) return Promise.reject(new DnsLookupError(name, rrtype, entry.fail));
    return Promise.resolve(entry ? (pick(entry) ?? []) : []);
  };
  return {
    queries,
    txt: (name) => lookup("TXT", name, (n) => n.txt),
    caa: (name) => lookup("CAA", name, (n) => n.caa),
  };
}

export const caa = (tag: string, value: string, critical = false): CaaRecord => ({
  critical,
  tag,
  value,
});
