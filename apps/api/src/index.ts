/**
 * @header-auditor/api: Fastify REST API with session auth. Later steps add
 * sites and the scan queue.
 */
export * from "./auth/index.js";
export { BASELINE_HEADERS, buildApp, type BuildAppOptions } from "./app.js";
export {
  type ApiConfig,
  type AuthConfig,
  CONFIG_KEYS,
  ConfigError,
  type Env,
  isBindableHost,
  loadConfig,
  LOG_LEVELS,
  type LogLevel,
  NODE_ENVS,
  type NodeEnv,
  normalizeOrigin,
} from "./config.js";
export {
  AppError,
  type AppErrorOptions,
  type ClassifiedError,
  classifyError,
  type ErrorBody,
  type ErrorDetail,
  errorBody,
  errorHandler,
  INTERNAL_ERROR_MESSAGE,
  notFoundHandler,
} from "./errors.js";
export {
  type CheckStatus,
  type HealthCheck,
  HealthCheckTimeoutError,
  type ReadinessResult,
  registerHealthRoutes,
  runCheck,
  validateHealthChecks,
} from "./health.js";
export {
  generateRequestId,
  loggerOptions,
  REDACT_PATHS,
  REDACTED,
  REQUEST_ID_HEADER,
  serializeRequest,
  stripQuery,
} from "./logger.js";
export {
  createShutdown,
  type ShutdownOptions,
  type ShutdownSignal,
  start,
  type StartOptions,
} from "./server.js";
