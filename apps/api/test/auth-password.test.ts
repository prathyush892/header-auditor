import { describe, expect, it } from "vitest";

import {
  createPasswordHasher,
  DEFAULT_ARGON2_PARAMS,
  normalizePassword,
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
  passwordProblems,
} from "../src/auth/password.js";
import { FAST_ARGON2, fastHasher, PASSWORD } from "./helpers/auth.js";

describe("createPasswordHasher", () => {
  it("uses argon2id with the OWASP parameters by default", async () => {
    const hasher = createPasswordHasher();
    const stored = await hasher.hash(PASSWORD);
    expect(stored).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/);
    expect(await hasher.verify(stored, PASSWORD)).toBe(true);
    expect(hasher.needsRehash(stored)).toBe(false);
    expect(DEFAULT_ARGON2_PARAMS).toEqual({ memoryCost: 19_456, timeCost: 2, parallelism: 1 });
  });

  it("salts every hash", async () => {
    const hasher = fastHasher();
    const [a, b] = await Promise.all([hasher.hash(PASSWORD), hasher.hash(PASSWORD)]);
    expect(a).not.toBe(b);
    expect(a).not.toContain(PASSWORD);
  });

  it("rejects the wrong password", async () => {
    const hasher = fastHasher();
    const stored = await hasher.hash(PASSWORD);
    expect(await hasher.verify(stored, PASSWORD + "!")).toBe(false);
    expect(await hasher.verify(stored, "")).toBe(false);
  });

  it.each(["", "not-a-hash", "$2b$12$bcrypthashlookingthing", "$argon2id$v=19$m=x"])(
    "returns false (not throw) for malformed stored hash %j",
    async (stored) => {
      expect(await fastHasher().verify(stored, PASSWORD)).toBe(false);
    },
  );

  it("verifies composed and decomposed Unicode as the same password", async () => {
    const hasher = fastHasher();
    const composed = "café au lait, s'il vous plaît";
    const decomposed = composed.normalize("NFD");
    expect(decomposed).not.toBe(composed);
    expect(await hasher.verify(await hasher.hash(composed), decomposed)).toBe(true);
  });

  it("flags hashes made with other parameters for rehashing", async () => {
    const weak = await fastHasher().hash(PASSWORD);
    const strong = createPasswordHasher({ ...FAST_ARGON2, timeCost: 2 });
    expect(strong.needsRehash(weak)).toBe(true);
    expect(await strong.verify(weak, PASSWORD)).toBe(true);
    expect(strong.needsRehash(await strong.hash(PASSWORD))).toBe(false);
    expect(strong.needsRehash("$argon2i$v=19$m=64,t=2,p=1$abc$def")).toBe(true);
    expect(strong.needsRehash("garbage")).toBe(true);
  });

  it("burn() runs a verification and resolves", async () => {
    const hasher = fastHasher();
    await expect(hasher.burn(PASSWORD)).resolves.toBeUndefined();
    await expect(hasher.burn("another")).resolves.toBeUndefined();
  });

  it.each([
    { memoryCost: 4, timeCost: 1, parallelism: 1 },
    { memoryCost: 64, timeCost: 0, parallelism: 1 },
    { memoryCost: 64, timeCost: 1, parallelism: 0 },
    { memoryCost: 64.5, timeCost: 1, parallelism: 1 },
    { memoryCost: 64, timeCost: 1, parallelism: 17 },
  ])("rejects unsafe parameters %j", (params) => {
    expect(() => createPasswordHasher(params)).toThrow(RangeError);
  });
});

describe("passwordProblems", () => {
  it("accepts a long passphrase", () => {
    expect(passwordProblems(PASSWORD, "user@example.test")).toEqual([]);
  });

  it("enforces the length bounds in code points", () => {
    expect(passwordProblems("a1".repeat(7))).toEqual([
      `must be at least ${String(PASSWORD_MIN_LENGTH)} characters`,
    ]);
    expect(passwordProblems("ab".repeat(PASSWORD_MAX_LENGTH))).toEqual([
      `must be at most ${String(PASSWORD_MAX_LENGTH)} characters`,
    ]);
    // 15 emoji = 15 code points (30 UTF-16 units): allowed.
    expect(passwordProblems("🔐🔑".repeat(8).slice(0, 2 * 15))).toEqual([]);
    expect(passwordProblems("🔐".repeat(14))).toHaveLength(2);
  });

  it("rejects whitespace-only and single-character passwords", () => {
    expect(passwordProblems(" ".repeat(20))).toContain("must not be only whitespace");
    expect(passwordProblems("a".repeat(20))).toEqual(["must not be a single repeated character"]);
  });

  it("rejects the account's own email address", () => {
    expect(passwordProblems("Long.Name@Example.test", "long.name@example.test")).toEqual([
      "must not be your email address",
    ]);
  });

  it("normalises before measuring", () => {
    expect(normalizePassword("é")).toBe("é");
  });
});
