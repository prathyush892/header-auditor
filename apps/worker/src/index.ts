/**
 * @header-auditor/worker: consumes the scan queue, runs @header-auditor/core
 * and stores results in Postgres. `main.ts` is the process entry point.
 */
export {
  type Env,
  LOG_LEVELS,
  loadWorkerConfig,
  type LogLevel,
  SCAN_PHASES,
  WORKER_CONFIG_KEYS,
  type WorkerConfig,
  WorkerConfigError,
} from "./config.js";
export {
  engineFindingRows,
  type EngineOptions,
  type EngineResult,
  FAILURE_MESSAGES,
  runEngine,
  type Section,
  storedReport,
  TargetError,
} from "./engine.js";
export { createLogger, REDACT_PATHS } from "./logger.js";
export { main, type RunningWorker } from "./main.js";
export {
  createPrismaWorkerStore,
  type PrismaWorkerClient,
  type PrismaWorkerTransaction,
} from "./prisma-store.js";
export {
  createScanProcessor,
  type ProcessOutcome,
  type ProcessorDeps,
  type ProcessorLogger,
  type RunEngine,
} from "./processor.js";
export {
  ABANDONED_MESSAGE,
  type ClaimedScan,
  type Grade,
  INTERNAL_FAILURE_MESSAGE,
  MemoryWorkerScanStore,
  type ScanLease,
  type ScanSuccess,
  type WorkerScanStore,
} from "./store.js";
export { startScanWorker, type StartWorkerOptions } from "./worker.js";
