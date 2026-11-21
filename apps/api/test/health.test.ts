import { afterEach, describe, expect, it } from "vitest";

import {
  type HealthCheck,
  HealthCheckTimeoutError,
  runCheck,
  validateHealthChecks,
} from "../src/health.js";
import { createTestApp, type TestApp } from "./helpers/app.js";

const ok = (name: string): HealthCheck => ({ name, check: () => Promise.resolve() });
const failing = (name: string, message: string): HealthCheck => ({
  name,
  check: () => Promise.reject(new Error(message)),
});

describe("validateHealthChecks", () => {
  it("accepts unique lower-case names", () => {
    expect(() => {
      validateHealthChecks([ok("database"), ok("redis"), ok("queue_v2")]);
    }).not.toThrow();
  });

  it.each(["", "Database", "1db", "has space", "x".repeat(33)])("rejects name %j", (name) => {
    expect(() => {
      validateHealthChecks([ok(name)]);
    }).toThrow(TypeError);
  });

  it("rejects duplicates", () => {
    expect(() => {
      validateHealthChecks([ok("db"), ok("db")]);
    }).toThrow(/Duplicate/);
  });
});

describe("runCheck", () => {
  it("resolves for a healthy check", async () => {
    await expect(runCheck(ok("db"), 100)).resolves.toBeUndefined();
  });

  it("rejects with the check's error", async () => {
    await expect(runCheck(failing("db", "down"), 100)).rejects.toThrow("down");
  });

  it("turns a synchronous throw into a rejection", async () => {
    const check: HealthCheck = {
      name: "sync",
      check: () => {
        throw new Error("sync boom");
      },
    };
    await expect(runCheck(check, 100)).rejects.toThrow("sync boom");
  });

  it("times out a hanging check and aborts its signal", async () => {
    let seen: AbortSignal | undefined;
    const check: HealthCheck = {
      name: "slow",
      check: (signal) => {
        seen = signal;
        return new Promise(() => undefined);
      },
    };
    await expect(runCheck(check, 20)).rejects.toBeInstanceOf(HealthCheckTimeoutError);
    expect(seen?.aborted).toBe(true);
    expect(seen?.reason).toBeInstanceOf(HealthCheckTimeoutError);
  });
});

describe("health routes", () => {
  let ctx: TestApp | undefined;

  afterEach(async () => {
    await ctx?.app.close();
    ctx = undefined;
  });

  it("GET /health is a dependency-free liveness probe", async () => {
    ctx = await createTestApp({ healthChecks: [failing("database", "down")] });
    const response = await ctx.app.inject("/health");
    expect(response.statusCode).toBe(200);
    const body = response.json<{ status: string; uptimeSeconds: number }>();
    expect(body.status).toBe("ok");
    expect(Number.isInteger(body.uptimeSeconds)).toBe(true);
  });

  it("GET /health/ready is ok with no checks registered", async () => {
    ctx = await createTestApp();
    const response = await ctx.app.inject("/health/ready");
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: "ok", checks: {} });
  });

  it("GET /health/ready reports each check", async () => {
    ctx = await createTestApp({ healthChecks: [ok("database"), ok("redis")] });
    const response = await ctx.app.inject("/health/ready");
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: "ok", checks: { database: "ok", redis: "ok" } });
  });

  it("returns 503 when any check fails, without leaking the error", async () => {
    ctx = await createTestApp({
      healthChecks: [
        ok("redis"),
        failing("database", "password authentication failed for user admin at 10.0.0.7"),
      ],
      env: { API_READINESS_TIMEOUT_MS: "200" },
    });
    const response = await ctx.app.inject("/health/ready");
    expect(response.statusCode).toBe(503);
    expect(response.json()).toEqual({
      status: "unavailable",
      checks: { redis: "ok", database: "fail" },
    });
    expect(response.body).not.toContain("10.0.0.7");
    const warning = ctx.logs.lines.find((line) => line.msg === "readiness check failed");
    expect(warning).toMatchObject({ level: 40, check: "database" });
    expect(JSON.stringify(warning)).toContain("10.0.0.7");
  });

  it("runs checks in parallel and fails a hanging one at the timeout", async () => {
    const hang: HealthCheck = { name: "slow", check: () => new Promise(() => undefined) };
    ctx = await createTestApp({
      healthChecks: [hang, ok("fast")],
      env: { API_READINESS_TIMEOUT_MS: "100" },
    });
    const started = Date.now();
    const response = await ctx.app.inject("/health/ready");
    expect(Date.now() - started).toBeLessThan(2_000);
    expect(response.statusCode).toBe(503);
    expect(response.json()).toEqual({
      status: "unavailable",
      checks: { slow: "fail", fast: "ok" },
    });
  });

  it("refuses to build with invalid check names", async () => {
    await expect(createTestApp({ healthChecks: [ok("Bad Name")] })).rejects.toThrow(TypeError);
  });
});
