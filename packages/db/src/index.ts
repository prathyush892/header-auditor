/**
 * @header-auditor/db: Prisma schema, migrations and a typed client for the
 * API and worker.
 */
export {
  createPrismaClient,
  DEFAULT_CONNECTION_TIMEOUT_MS,
  DEFAULT_MAX_CONNECTIONS,
  type CreateClientOptions,
} from "./client.js";
export { DatabaseConfigError, parseDatabaseUrl, redactDatabaseUrl } from "./config.js";
export {
  CHECK_NAME_MAX_LENGTH,
  findingRows,
  fromDbFindingStatus,
  stripNul,
  toDbFindingStatus,
  toDbGrade,
  toDbScore,
  type EngineFinding,
  type EngineGrade,
  type FindingRow,
} from "./mappers.js";
export * from "./generated/prisma/client.js";
