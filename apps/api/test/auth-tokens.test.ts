import { describe, expect, it } from "vitest";

import {
  deriveCsrfToken,
  generateSessionToken,
  hashSessionToken,
  isWellFormedSessionToken,
  verifyCsrfToken,
} from "../src/auth/tokens.js";

describe("session tokens", () => {
  it("are 256-bit base64url strings and never repeat", () => {
    const tokens = new Set(Array.from({ length: 1_000 }, generateSessionToken));
    expect(tokens.size).toBe(1_000);
    for (const token of tokens) {
      expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(Buffer.from(token, "base64url")).toHaveLength(32);
    }
  });

  it("hash to lower-case hex SHA-256 (the only form stored)", () => {
    const token = generateSessionToken();
    const digest = hashSessionToken(token);
    expect(digest).toMatch(/^[0-9a-f]{64}$/);
    expect(hashSessionToken(token)).toBe(digest);
    expect(digest).not.toContain(token);
  });

  it.each([
    [undefined, false],
    [123, false],
    ["", false],
    ["a".repeat(42), false],
    ["a".repeat(44), false],
    ["a".repeat(42) + "=", false],
    ["a".repeat(42) + "+", false],
    ["' OR 1=1 --" + "a".repeat(32), false],
    ["a".repeat(43), true],
  ])("isWellFormedSessionToken(%j) is %s", (value, expected) => {
    expect(isWellFormedSessionToken(value)).toBe(expected);
  });
});

describe("CSRF tokens", () => {
  it("are derived deterministically from the session token", () => {
    const token = generateSessionToken();
    expect(deriveCsrfToken(token)).toBe(deriveCsrfToken(token));
    expect(deriveCsrfToken(token)).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("differ per session and don't reveal the session token", () => {
    const a = generateSessionToken();
    const b = generateSessionToken();
    expect(deriveCsrfToken(a)).not.toBe(deriveCsrfToken(b));
    expect(deriveCsrfToken(a)).not.toBe(a);
    expect(deriveCsrfToken(a)).not.toBe(hashSessionToken(a));
  });

  it("verify only the token for the same session", () => {
    const a = generateSessionToken();
    const b = generateSessionToken();
    expect(verifyCsrfToken(a, deriveCsrfToken(a))).toBe(true);
    expect(verifyCsrfToken(a, deriveCsrfToken(b))).toBe(false);
  });

  it.each([undefined, "", ["array"], 42, "x".repeat(43), "x".repeat(1_000)])(
    "rejects presented value %j",
    (presented) => {
      expect(verifyCsrfToken(generateSessionToken(), presented)).toBe(false);
    },
  );

  it("rejects a token that differs only in the last character", () => {
    const token = generateSessionToken();
    const csrf = deriveCsrfToken(token);
    const tampered = csrf.slice(0, -1) + (csrf.endsWith("A") ? "B" : "A");
    expect(verifyCsrfToken(token, tampered)).toBe(false);
  });
});
