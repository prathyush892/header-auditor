/**
 * @header-auditor/queue: the contract between the API, which enqueues scans,
 * and the worker, which runs them.
 *
 * Both sides import the queue name, the job payload validator and the job
 * options from here, so a renamed queue or a changed payload is a compile
 * error in both apps instead of jobs silently piling up where nobody listens.
 *
 * The package has no runtime dependencies: it returns plain objects that
 * BullMQ and ioredis accept, so it never pins their versions for its users.
 */
export {
  parseScanJobData,
  SCAN_JOB_NAME,
  SCAN_QUEUE_NAME,
  ScanJobDataError,
  scanJobOptions,
  type ScanJobData,
  type ScanJobOptions,
  DEFAULT_QUEUE_PREFIX,
  isQueuePrefix,
  SCAN_JOB_ATTEMPTS,
  SCAN_JOB_BACKOFF_MS,
} from "./job.js";
export {
  parseRedisUrl,
  RedisUrlError,
  redactRedisUrl,
  redisConnectionOptions,
  type RedisConnectionOptions,
  type RedisRole,
} from "./redis.js";
