import { describe, expect, it } from "vitest";

import {
  ApiError,
  ApiNetworkError,
  ApiResponseError,
  describeError,
  fieldErrors,
  parseRetryAfter,
  UNEXPECTED_RESPONSE,
} from "@/lib/api";
import { authErrorMessages } from "@/lib/auth-errors";

function apiError(overrides: Partial<ConstructorParameters<typeof ApiError>[0]> = {}): ApiError {
  return new ApiError({ status: 400, code: "BAD_REQUEST", message: "Bad request", ...overrides });
}

describe("fieldErrors", () => {
  it("groups details by path and sends <root> to _form", () => {
    const error = apiError({
      details: [
        { path: "password", message: "must be at least 15 characters" },
        { path: "password", message: "must not be your email address" },
        { path: "<root>", message: "unknown key" },
        { path: "email", message: "must be a valid email address" },
      ],
    });
    expect(fieldErrors(error)).toEqual({
      password: ["must be at least 15 characters", "must not be your email address"],
      _form: ["unknown key"],
      email: ["must be a valid email address"],
    });
  });

  it("is empty without details", () => {
    expect(fieldErrors(apiError())).toEqual({});
  });

  it("can't be tricked into writing Object.prototype", () => {
    const grouped = fieldErrors(apiError({ details: [{ path: "__proto__", message: "x" }] }));
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.getPrototypeOf({})).toBe(Object.prototype);
    expect(Object.keys(grouped)).toEqual(["__proto__"]);
  });
});

describe("parseRetryAfter", () => {
  const now = Date.parse("2026-11-27T12:00:00Z");

  it("reads delta-seconds", () => {
    expect(parseRetryAfter("120", now)).toBe(120);
    expect(parseRetryAfter(" 7 ", now)).toBe(7);
  });

  it("reads an HTTP date", () => {
    expect(parseRetryAfter("Fri, 27 Nov 2026 12:01:30 GMT", now)).toBe(90);
    expect(parseRetryAfter("Fri, 27 Nov 2026 11:00:00 GMT", now)).toBe(0);
  });

  it("returns null for missing or garbage values", () => {
    expect(parseRetryAfter(null, now)).toBeNull();
    expect(parseRetryAfter("soon", now)).toBeNull();
    expect(parseRetryAfter("-5", now)).toBeNull();
  });
});

describe("describeError", () => {
  it("shows the API's message for client errors", () => {
    expect(describeError(apiError({ message: "Site not found" }))).toBe("Site not found");
  });

  it("formats rate limits with the wait", () => {
    expect(describeError(apiError({ status: 429, retryAfterSeconds: 30 }))).toMatch(/30 seconds/);
    expect(describeError(apiError({ status: 429, retryAfterSeconds: 61 }))).toMatch(/2 minutes/);
    expect(describeError(apiError({ status: 429, retryAfterSeconds: 60 }))).toMatch(/1 minute\b/);
    expect(describeError(apiError({ status: 429 }))).toMatch(/try again later/i);
  });

  it("hides server details but gives the request id", () => {
    const message = describeError(
      apiError({ status: 500, code: "INTERNAL_ERROR", message: "db exploded", requestId: "req-1" }),
    );
    expect(message).not.toContain("db exploded");
    expect(message).toContain("req-1");
  });

  it("treats a foreign error body as a server problem", () => {
    expect(describeError(apiError({ status: 502, code: UNEXPECTED_RESPONSE }))).toMatch(/our side/);
  });

  it("explains network failures and timeouts", () => {
    expect(describeError(new ApiNetworkError("x", {}))).toMatch(/can't reach/i);
    expect(describeError(new ApiNetworkError("x", { timedOut: true }))).toMatch(/too long/i);
  });

  it("has a generic fallback", () => {
    expect(describeError(new ApiResponseError("x", { status: 200, path: "/x" }))).toMatch(
      /something went wrong/i,
    );
    expect(describeError("weird")).toMatch(/something went wrong/i);
  });
});

describe("authErrorMessages", () => {
  it("uses one message for wrong email or wrong password", () => {
    expect(authErrorMessages(apiError({ status: 401, code: "INVALID_CREDENTIALS" }))).toEqual({
      _form: "That email and password don't match an account.",
    });
  });

  it("puts EMAIL_TAKEN on the email field", () => {
    expect(authErrorMessages(apiError({ status: 409, code: "EMAIL_TAKEN" })).email).toMatch(
      /already exists/,
    );
  });

  it("maps validation details onto the fields as sentences", () => {
    const error = apiError({
      code: "VALIDATION_FAILED",
      details: [
        { path: "password", message: "must be at least 15 characters" },
        { path: "email", message: "must be a valid email address" },
      ],
    });
    expect(authErrorMessages(error)).toEqual({
      password: "Must be at least 15 characters.",
      email: "Must be a valid email address.",
    });
  });

  it("falls back to a form message for validation errors on other paths", () => {
    const error = apiError({
      code: "VALIDATION_FAILED",
      message: "Request validation failed",
      details: [{ path: "<root>", message: "Unrecognized key" }],
    });
    expect(authErrorMessages(error)).toEqual({ _form: "Request validation failed" });
  });

  it("describes anything else at form level", () => {
    expect(authErrorMessages(new ApiNetworkError("x", {}))._form).toMatch(/can't reach/i);
    expect(authErrorMessages(apiError({ status: 429, retryAfterSeconds: 5 }))._form).toMatch(
      /5 seconds/,
    );
  });
});
