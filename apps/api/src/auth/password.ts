/**
 * Password hashing (argon2id) and the password policy.
 *
 * argon2id is memory-hard: every guess costs the attacker ~19 MiB of RAM, so
 * GPU/ASIC cracking of a stolen hash table is far slower than with bcrypt or
 * a plain SHA. The encoded hash carries the algorithm, parameters and salt,
 * so parameters can be raised later and old hashes still verify (and are
 * re-hashed on the next successful login via `needsRehash`).
 */
import { randomBytes } from "node:crypto";

import { type Algorithm, hash, verify } from "@node-rs/argon2";

/**
 * `Algorithm` is an ambient const enum, which `verbatimModuleSyntax` can't
 * read at runtime; 2 is its `Argon2id` member (the type annotation checks it).
 */
// eslint-disable-next-line @typescript-eslint/no-unsafe-enum-assignment -- see above
const ARGON2ID: Algorithm.Argon2id = 2;

export interface Argon2Params {
  /** Memory in KiB. */
  readonly memoryCost: number;
  /** Iterations. */
  readonly timeCost: number;
  /** Lanes. */
  readonly parallelism: number;
}

/** OWASP Password Storage Cheat Sheet, argon2id option 2 (m=19 MiB, t=2, p=1). */
export const DEFAULT_ARGON2_PARAMS: Argon2Params = Object.freeze({
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
});

/** NIST SP 800-63B rev. 4: at least 15 characters when the password is the only factor. */
export const PASSWORD_MIN_LENGTH = 15;
/** Long enough for any passphrase or manager; bounded so hashing can't be used for DoS. */
export const PASSWORD_MAX_LENGTH = 128;

export interface PasswordHasher {
  hash(password: string): Promise<string>;
  /** Never throws for a malformed stored hash; returns false instead. */
  verify(storedHash: string, password: string): Promise<boolean>;
  /** True when `storedHash` used weaker (or different) parameters than this hasher. */
  needsRehash(storedHash: string): boolean;
  /**
   * Runs a full verification against a throwaway hash. Called when the email
   * is unknown so "no such user" takes as long as "wrong password".
   */
  burn(password: string): Promise<void>;
}

const PARAM_PATTERN = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$/;

function checkParams(params: Argon2Params): Argon2Params {
  const { memoryCost, timeCost, parallelism } = params;
  if (!Number.isInteger(memoryCost) || memoryCost < 8 * parallelism || memoryCost > 4_194_304) {
    throw new RangeError("memoryCost must be an integer KiB value >= 8 * parallelism");
  }
  if (!Number.isInteger(timeCost) || timeCost < 1 || timeCost > 100) {
    throw new RangeError("timeCost must be an integer in [1, 100]");
  }
  if (!Number.isInteger(parallelism) || parallelism < 1 || parallelism > 16) {
    throw new RangeError("parallelism must be an integer in [1, 16]");
  }
  return params;
}

/**
 * Unicode NFC so the same passphrase typed on macOS and Windows (composed vs
 * decomposed accents) hashes identically. Applied before hashing and verifying.
 */
export function normalizePassword(password: string): string {
  return password.normalize("NFC");
}

export function createPasswordHasher(params: Argon2Params = DEFAULT_ARGON2_PARAMS): PasswordHasher {
  const options = { ...checkParams(params), algorithm: ARGON2ID } as const;
  let dummyHash: Promise<string> | undefined;

  const hasher: PasswordHasher = {
    hash: (password) => hash(normalizePassword(password), options),
    async verify(storedHash, password) {
      try {
        return await verify(storedHash, normalizePassword(password));
      } catch {
        // Corrupt or non-argon2 hash in the database: treat as a failed login.
        return false;
      }
    },
    needsRehash(storedHash) {
      const match = PARAM_PATTERN.exec(storedHash);
      if (match === null) return true;
      const [, m, t, p] = match.map(Number);
      return m !== options.memoryCost || t !== options.timeCost || p !== options.parallelism;
    },
    async burn(password) {
      dummyHash ??= hash(randomBytes(32).toString("base64url"), options);
      await hasher.verify(await dummyHash, password);
    },
  };
  return hasher;
}

/** Problems with a new password, or an empty list. Applied at registration, not at login. */
export function passwordProblems(password: string, email?: string): string[] {
  const normalized = normalizePassword(password);
  // NIST 800-63B counts each Unicode code point as one character (not UTF-16
  // units, and not grapheme clusters), which is exactly what spreading gives.
  // eslint-disable-next-line @typescript-eslint/no-misused-spread
  const length = [...normalized].length;
  const problems: string[] = [];
  if (length < PASSWORD_MIN_LENGTH) {
    problems.push(`must be at least ${String(PASSWORD_MIN_LENGTH)} characters`);
  }
  if (length > PASSWORD_MAX_LENGTH) {
    problems.push(`must be at most ${String(PASSWORD_MAX_LENGTH)} characters`);
  }
  if (normalized.trim() === "" && length > 0) problems.push("must not be only whitespace");
  if (length > 0 && new Set(normalized).size === 1) {
    problems.push("must not be a single repeated character");
  }
  if (email !== undefined && email.length > 0 && normalized.toLowerCase() === email.toLowerCase()) {
    problems.push("must not be your email address");
  }
  return problems;
}
