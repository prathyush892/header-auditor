export {
  type AuthContext,
  type AuthOptions,
  CSRF_HEADER,
  DEFAULT_PRUNE_INTERVAL_MS,
  DEV_COOKIE_NAME,
  isTrustedOrigin,
  type PublicUser,
  registerAuth,
  requireAuth,
  sanitizeUserAgent,
  SECURE_COOKIE_NAME,
  sessionCookieName,
  type SessionResponse,
  toPublicUser,
  TOUCH_INTERVAL_MS,
} from "./plugin.js";
export {
  type Argon2Params,
  createPasswordHasher,
  DEFAULT_ARGON2_PARAMS,
  normalizePassword,
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
  type PasswordHasher,
  passwordProblems,
} from "./password.js";
export { createPrismaAuthStore, isUniqueViolation, type PrismaAuthClient } from "./prisma-store.js";
export {
  DEFAULT_MAX_KEYS,
  MemoryRateLimiter,
  type MemoryRateLimiterOptions,
  type RateLimitDecision,
  type RateLimiter,
} from "./rate-limit.js";
export {
  type AuthStore,
  EmailTakenError,
  isSessionExpired,
  MemoryAuthStore,
  type NewSession,
  type SessionRecord,
  type UserRecord,
} from "./store.js";
export {
  deriveCsrfToken,
  generateSessionToken,
  hashSessionToken,
  isWellFormedSessionToken,
  SESSION_TOKEN_BYTES,
  verifyCsrfToken,
} from "./tokens.js";
