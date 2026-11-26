/**
 * Re-exports packages/core's DNS test helpers: an in-memory resolver and a
 * tiny UDP DNS server bound to 127.0.0.1 (so the real c-ares resolver can be
 * exercised without touching any public nameserver).
 */
export { fixtureResolver } from "../../../../packages/core/test/helpers/dns-fixture.js";
export { startDnsServer } from "../../../../packages/core/test/helpers/dns-server.js";
