import { describe, expect, it } from "vitest";

import {
  hasErrors,
  normalizeEmail,
  PASSWORD_MAX_LENGTH,
  validateLogin,
  validateRegistration,
} from "@/lib/validation";

const GOOD = "correct horse battery staple";

describe("validateLogin", () => {
  it("accepts any non-empty password (old passwords must keep working)", () => {
    expect(validateLogin({ email: "a@example.com", password: "x" })).toEqual({});
  });

  it("requires both fields", () => {
    const errors = validateLogin({ email: " ", password: "" });
    expect(errors.email).toMatch(/enter your email/i);
    expect(errors.password).toMatch(/enter your password/i);
  });

  it("rejects a malformed email", () => {
    expect(validateLogin({ email: "not-an-email", password: "x" }).email).toMatch(/valid/i);
  });
});

describe("validateRegistration", () => {
  it("accepts a passphrase", () => {
    const errors = validateRegistration({ email: "Ada@Example.com", password: GOOD });
    expect(errors).toEqual({});
    expect(hasErrors(errors)).toBe(false);
  });

  it.each([
    ["too short", "short pass", /at least 15/],
    ["too long", "x".repeat(PASSWORD_MAX_LENGTH) + "y", /at most 128/],
    ["only spaces", " ".repeat(20), /only spaces/],
    ["one repeated character", "a".repeat(20), /repeated/],
  ])("rejects a password that is %s", (_label, password, message) => {
    expect(validateRegistration({ email: "a@example.com", password }).password).toMatch(message);
  });

  it("rejects the email address as the password, ignoring case", () => {
    const email = "someone.long@example.com";
    expect(validateRegistration({ email, password: email.toUpperCase() }).password).toMatch(
      /email/,
    );
  });

  it("counts code points like the API: 15 emoji are 15 characters", () => {
    expect(validateRegistration({ email: "a@example.com", password: "🔒🔑".repeat(8) })).toEqual(
      {},
    );
    expect(
      validateRegistration({ email: "a@example.com", password: "🔒🔑".repeat(7) }).password,
    ).toMatch(/at least/);
  });

  it("normalizes NFC so a decomposed accent counts as one character", () => {
    const decomposed = "é".repeat(14) + "x"; // 15 characters after NFC
    expect(validateRegistration({ email: "a@example.com", password: decomposed })).toEqual({});
  });
});

describe("normalizeEmail", () => {
  it("trims and lower-cases like the API", () => {
    expect(normalizeEmail("  Ada@Example.COM ")).toBe("ada@example.com");
  });
});
