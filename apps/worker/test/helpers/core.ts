/**
 * Re-exports packages/core's test helpers: a throwaway PKI (openssl, temp
 * dir, nothing committed) and an in-memory DNS resolver.
 */
export { TestPki } from "../../../../packages/core/test/helpers/pki.js";
export { caa, fixtureResolver } from "../../../../packages/core/test/helpers/dns-fixture.js";
