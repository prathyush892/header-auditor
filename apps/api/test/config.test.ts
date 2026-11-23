import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  CONFIG_KEYS,
  ConfigError,
  isBindableHost,
  loadConfig,
  normalizeOrigin,
} from "../src/config.js";

function problemsFor(env: Record<string, string>): readonly string[] {
  try {
    loadConfig(env);
  } catch (error) {
    expect(error).toBeInstanceOf(ConfigError);
    return (error as ConfigError).problems;
  }
  throw new Error("expected loadConfig to throw");
}

describe("loadConfig", () => {
  it("uses safe defaults for an empty environment", () => {
    expect(loadConfig({})).toEqual({
      nodeEnv: "development",
      logLevel: "info",
      host: "127.0.0.1",
      port: 3001,
      trustProxy: false,
      bodyLimitBytes: 1_048_576,
      requestTimeoutMs: 30_000,
      shutdownTimeoutMs: 10_000,
      readinessTimeoutMs: 2_000,
      allowedOrigins: ["http://localhost:3000"],
      auth: {
        cookieSecure: true,
        sessionTtlMs: 7 * 24 * 3_600_000,
        sessionIdleMs: 12 * 3_600_000,
        rateLimit: { windowMs: 900_000, perAccount: 10, perIp: 100 },
      },
    });
  });

  it("parses every supported variable", () => {
    const config = loadConfig({
      NODE_ENV: "production",
      LOG_LEVEL: "warn",
      API_HOST: "0.0.0.0",
      API_PORT: "8080",
      API_TRUST_PROXY: "true",
      API_BODY_LIMIT_BYTES: "65536",
      API_REQUEST_TIMEOUT_MS: "5000",
      API_SHUTDOWN_TIMEOUT_MS: "2000",
      API_READINESS_TIMEOUT_MS: "500",
    });
    expect(config).toMatchObject({
      nodeEnv: "production",
      logLevel: "warn",
      host: "0.0.0.0",
      port: 8080,
      trustProxy: true,
      bodyLimitBytes: 65_536,
      requestTimeoutMs: 5_000,
      shutdownTimeoutMs: 2_000,
      readinessTimeoutMs: 500,
    });
  });

  it("returns a frozen object", () => {
    expect(Object.isFrozen(loadConfig({}))).toBe(true);
  });

  it("defaults to process.env", () => {
    expect(loadConfig().port).toBeTypeOf("number");
  });

  it("treats empty and whitespace-only values as unset", () => {
    const config = loadConfig({ API_PORT: "", LOG_LEVEL: "   ", API_TRUST_PROXY: "" });
    expect(config.port).toBe(3001);
    expect(config.logLevel).toBe("info");
    expect(config.trustProxy).toBe(false);
  });

  it("trims surrounding whitespace", () => {
    expect(loadConfig({ API_PORT: " 4000 ", API_HOST: " localhost " })).toMatchObject({
      port: 4000,
      host: "localhost",
    });
  });

  it("ignores unrelated environment variables", () => {
    expect(() =>
      loadConfig({ PATH: "/usr/bin", DATABASE_URL: "not a url", HOME: "" }),
    ).not.toThrow();
  });

  it("only declares API/AUTH keys plus NODE_ENV and LOG_LEVEL", () => {
    expect([...CONFIG_KEYS].sort()).toEqual(
      [
        "API_ALLOWED_ORIGINS",
        "API_BODY_LIMIT_BYTES",
        "API_HOST",
        "API_PORT",
        "API_READINESS_TIMEOUT_MS",
        "API_REQUEST_TIMEOUT_MS",
        "API_SHUTDOWN_TIMEOUT_MS",
        "API_TRUST_PROXY",
        "AUTH_COOKIE_SECURE",
        "AUTH_RATE_LIMIT_PER_ACCOUNT",
        "AUTH_RATE_LIMIT_PER_IP",
        "AUTH_RATE_LIMIT_WINDOW_SECONDS",
        "AUTH_SESSION_IDLE_MINUTES",
        "AUTH_SESSION_TTL_HOURS",
        "LOG_LEVEL",
        "NODE_ENV",
      ].sort(),
    );
  });

  it.each(["0", "1", "65535"])("accepts port %s", (port) => {
    expect(loadConfig({ API_PORT: port }).port).toBe(Number(port));
  });

  it.each(["65536", "-1", "80.5", "3001abc", "0x50", "1e3", "abc"])("rejects port %j", (port) => {
    expect(problemsFor({ API_PORT: port })).toEqual([expect.stringMatching(/^API_PORT: /)]);
  });

  it.each([
    ["true", true],
    ["TRUE", true],
    ["1", true],
    ["false", false],
    ["False", false],
    ["0", false],
  ])("parses API_TRUST_PROXY=%j as %s", (value, expected) => {
    expect(loadConfig({ API_TRUST_PROXY: value }).trustProxy).toBe(expected);
  });

  it.each(["yes", "no", "on", "2"])(
    "rejects ambiguous boolean %j instead of reading it as false",
    (value) => {
      expect(problemsFor({ API_TRUST_PROXY: value })).toEqual([
        expect.stringMatching(/^API_TRUST_PROXY: /),
      ]);
    },
  );

  it("rejects unknown NODE_ENV and LOG_LEVEL values", () => {
    const problems = problemsFor({ NODE_ENV: "staging", LOG_LEVEL: "verbose" });
    expect(problems).toHaveLength(2);
    expect(problems.join("\n")).toMatch(/NODE_ENV: .*production/);
    expect(problems.join("\n")).toMatch(/LOG_LEVEL: .*debug/);
  });

  it("enforces numeric bounds", () => {
    const problems = problemsFor({
      API_BODY_LIMIT_BYTES: "10",
      API_REQUEST_TIMEOUT_MS: "999999",
      API_SHUTDOWN_TIMEOUT_MS: "5",
      API_READINESS_TIMEOUT_MS: "99",
    });
    expect(problems.map((p) => p.split(":")[0]).sort()).toEqual([
      "API_BODY_LIMIT_BYTES",
      "API_READINESS_TIMEOUT_MS",
      "API_REQUEST_TIMEOUT_MS",
      "API_SHUTDOWN_TIMEOUT_MS",
    ]);
  });

  it("reports every problem at once", () => {
    const error = (() => {
      try {
        loadConfig({ API_PORT: "x", API_HOST: "http://x", LOG_LEVEL: "loud" });
      } catch (e) {
        return e as ConfigError;
      }
      throw new Error("expected throw");
    })();
    expect(error.problems).toHaveLength(3);
    expect(error.message).toContain("Invalid API configuration");
    expect(error.name).toBe("ConfigError");
  });

  it("never echoes the rejected value in errors", () => {
    const secretish = "s3cr3t-value-123";
    const error = (() => {
      try {
        loadConfig({
          API_PORT: secretish,
          NODE_ENV: secretish,
          API_HOST: `${secretish}:1`,
          API_TRUST_PROXY: secretish,
        });
      } catch (e) {
        return e as ConfigError;
      }
      throw new Error("expected throw");
    })();
    expect(error.problems).toHaveLength(4);
    expect(error.message).not.toContain(secretish);
  });
});

describe("API_HOST", () => {
  it.each([
    ["127.0.0.1", "127.0.0.1"],
    ["0.0.0.0", "0.0.0.0"],
    ["localhost", "localhost"],
    ["api.internal", "api.internal"],
    ["::", "::"],
    ["::1", "::1"],
    ["[::1]", "::1"],
  ])("accepts %j", (value, expected) => {
    expect(loadConfig({ API_HOST: value }).host).toBe(expected);
  });

  it.each([
    "http://0.0.0.0",
    "0.0.0.0:3001",
    "local host",
    "-bad.example",
    "a..b",
    "host/path",
    "[::1]:80",
    "x".repeat(254),
  ])("rejects %j", (value) => {
    expect(isBindableHost(value)).toBe(false);
    expect(problemsFor({ API_HOST: value })).toEqual([expect.stringMatching(/^API_HOST: /)]);
  });
});

describe("auth and origin settings", () => {
  it("parses auth settings into milliseconds", () => {
    expect(
      loadConfig({
        AUTH_COOKIE_SECURE: "false",
        AUTH_SESSION_TTL_HOURS: "2",
        AUTH_SESSION_IDLE_MINUTES: "30",
        AUTH_RATE_LIMIT_WINDOW_SECONDS: "60",
        AUTH_RATE_LIMIT_PER_ACCOUNT: "3",
        AUTH_RATE_LIMIT_PER_IP: "20",
      }).auth,
    ).toEqual({
      cookieSecure: false,
      sessionTtlMs: 7_200_000,
      sessionIdleMs: 1_800_000,
      rateLimit: { windowMs: 60_000, perAccount: 3, perIp: 20 },
    });
  });

  it("refuses insecure cookies in production", () => {
    expect(problemsFor({ NODE_ENV: "production", AUTH_COOKIE_SECURE: "false" })).toEqual([
      "AUTH_COOKIE_SECURE: must be true in production",
    ]);
  });

  it("refuses an idle timeout longer than the absolute lifetime", () => {
    expect(problemsFor({ AUTH_SESSION_TTL_HOURS: "1", AUTH_SESSION_IDLE_MINUTES: "61" })).toEqual([
      "AUTH_SESSION_IDLE_MINUTES: must not exceed AUTH_SESSION_TTL_HOURS",
    ]);
  });

  it.each([
    ["AUTH_SESSION_TTL_HOURS", "0"],
    ["AUTH_SESSION_IDLE_MINUTES", "1"],
    ["AUTH_RATE_LIMIT_PER_ACCOUNT", "0"],
    ["AUTH_RATE_LIMIT_WINDOW_SECONDS", "abc"],
    ["AUTH_COOKIE_SECURE", "yes"],
  ])("rejects %s=%s", (key, value) => {
    const problems = problemsFor({ [key]: value });
    expect(problems).toHaveLength(1);
    expect(problems[0]?.startsWith(`${key}: `)).toBe(true);
  });

  it("normalises and de-duplicates allowed origins", () => {
    expect(
      loadConfig({
        API_ALLOWED_ORIGINS:
          " https://App.Example.com:443 , http://localhost:3000,https://app.example.com ,",
      }).allowedOrigins,
    ).toEqual(["https://app.example.com", "http://localhost:3000"]);
  });

  it.each([
    "app.example.com",
    "https://app.example.com/dashboard",
    "https://app.example.com?x=1",
    "https://user:pw@app.example.com",
    "ftp://app.example.com",
    "javascript:alert(1)",
    "*",
    " , ",
  ])("rejects API_ALLOWED_ORIGINS=%j", (value) => {
    const problems = problemsFor({ API_ALLOWED_ORIGINS: value });
    expect(problems).toHaveLength(1);
    expect(problems[0]).toMatch(/^API_ALLOWED_ORIGINS: /);
    // Never echo the configured value back.
    if (value.trim().length > 3) expect(problems[0]).not.toContain(value.trim());
  });
});

describe("normalizeOrigin", () => {
  it.each([
    ["https://a.test", "https://a.test"],
    ["https://a.test/", "https://a.test"],
    ["http://A.TEST:80", "http://a.test"],
    ["http://127.0.0.1:3000", "http://127.0.0.1:3000"],
    ["http://[::1]:3000", "http://[::1]:3000"],
  ])("%s -> %s", (input, expected) => {
    expect(normalizeOrigin(input)).toBe(expected);
  });

  it.each(["", "a.test", "https://a.test/x", "https://a.test/.", "https://a.test#f", "data:,x"])(
    "rejects %j",
    (input) => {
      expect(normalizeOrigin(input)).toBeUndefined();
    },
  );
});

describe(".env.example", () => {
  it("documents every API variable with values that load to the defaults", () => {
    // Fixed repo file, not user input.
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    const text = readFileSync(new URL("../../../.env.example", import.meta.url), "utf8");
    const env = Object.fromEntries(
      text
        .split("\n")
        .filter((line) => /^[A-Z_]+=/.test(line))
        .map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]),
    );
    for (const key of CONFIG_KEYS) expect(env).toHaveProperty(key);
    expect(loadConfig({ ...env, NODE_ENV: "development" })).toEqual(loadConfig({}));
  });
});
