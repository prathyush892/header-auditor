/**
 * Re-exports packages/db's PGlite test database (WASM Postgres on 127.0.0.1
 * with the committed migrations applied) so API tests exercise the real SQL.
 */
export {
  startTestDatabase,
  type TestDatabase,
} from "../../../../packages/db/test/helpers/test-database.js";
