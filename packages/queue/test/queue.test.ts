import { describe, expect, it } from "vitest";

import {
  DEFAULT_QUEUE_PREFIX,
  isQueuePrefix,
  parseRedisUrl,
  parseScanJobData,
  RedisUrlError,
  redactRedisUrl,
  redisConnectionOptions,
  SCAN_JOB_ATTEMPTS,
  ScanJobDataError,
  scanJobOptions,
} from "../src/index.js";

const ID = "0b9d6c3e-6a0f-4c5e-9f51-3f0b3f2c9a10";

describe("parseScanJobData", () => {
  it("accepts exactly { scanId: <uuid> }", () => {
    expect(parseScanJobData({ scanId: ID })).toEqual({ scanId: ID });
  });

  it.each([
    ["null", null],
    ["a string", ID],
    ["an array", [ID]],
    ["no key", {}],
    ["an extra key", { scanId: ID, url: "http://169.254.169.254/" }],
    ["a different key", { id: ID }],
    ["a number", { scanId: 42 }],
    ["an upper-case uuid", { scanId: ID.toUpperCase() }],
    ["a non-uuid", { scanId: "../../etc/passwd" }],
    ["a uuid with suffix", { scanId: `${ID}x` }],
  ])("rejects %s", (_label, data) => {
    expect(() => parseScanJobData(data)).toThrow(ScanJobDataError);
  });

  it("does not consult the prototype chain", () => {
    const data = Object.create({ scanId: ID }) as unknown;
    expect(() => parseScanJobData(data)).toThrow(ScanJobDataError);
  });
});

describe("scanJobOptions", () => {
  it("uses the scan id as the job id so a scan is enqueued at most once", () => {
    const options = scanJobOptions(ID);
    expect(options.jobId).toBe(ID);
    expect(options.attempts).toBe(SCAN_JOB_ATTEMPTS);
    expect(options.backoff).toEqual({ type: "exponential", delay: 5_000 });
    expect(options.removeOnComplete.age).toBeGreaterThan(0);
    expect(options.removeOnFail.age).toBeGreaterThan(options.removeOnComplete.age);
  });

  it("refuses an invalid scan id", () => {
    expect(() => scanJobOptions("nope")).toThrow(ScanJobDataError);
  });
});

describe("isQueuePrefix", () => {
  it.each([DEFAULT_QUEUE_PREFIX, "test-1", "a.b_c"])("accepts %s", (value) => {
    expect(isQueuePrefix(value)).toBe(true);
  });

  it.each(["", "-x", "a:b", "a b", "x".repeat(65), "{tag}"])("rejects %j", (value) => {
    expect(isQueuePrefix(value)).toBe(false);
  });
});

describe("parseRedisUrl", () => {
  it("parses host, port, credentials and database", () => {
    expect(parseRedisUrl("redis://user:p%40ss@127.0.0.1:6380/2")).toEqual({
      host: "127.0.0.1",
      port: 6380,
      db: 2,
      username: "user",
      password: "p@ss",
      tls: false,
    });
  });

  it("defaults the port and database and supports password-only auth", () => {
    expect(parseRedisUrl("redis://:secret@localhost")).toEqual({
      host: "localhost",
      port: 6379,
      db: 0,
      username: undefined,
      password: "secret",
      tls: false,
    });
  });

  it("unwraps IPv6 literals and marks rediss:// as TLS", () => {
    const parsed = parseRedisUrl("rediss://[::1]:6379");
    expect(parsed.host).toBe("::1");
    expect(parsed.tls).toBe(true);
  });

  it.each([
    ["unset", undefined],
    ["blank", "  "],
    ["not a URL", "127.0.0.1:6379"],
    ["wrong scheme", "http://127.0.0.1:6379"],
    ["database out of range", "redis://127.0.0.1/16"],
    ["database not a number", "redis://127.0.0.1/abc"],
    ["query string", "redis://127.0.0.1/0?password=x"],
    ["bad percent-encoding", "redis://:%E0%A4%A@127.0.0.1"],
  ])("rejects %s", (_label, value) => {
    expect(() => parseRedisUrl(value)).toThrow(RedisUrlError);
  });

  it("never echoes the URL (and so the password) in errors", () => {
    try {
      parseRedisUrl("http://:hunter2@127.0.0.1");
      expect.unreachable();
    } catch (error) {
      expect(String(error)).not.toContain("hunter2");
    }
  });
});

describe("redisConnectionOptions", () => {
  it("makes producers fail fast and consumers block, as BullMQ requires", () => {
    const producer = redisConnectionOptions("redis://:pw@127.0.0.1:6379", "producer");
    const consumer = redisConnectionOptions("redis://:pw@127.0.0.1:6379", "consumer");
    expect(producer).toMatchObject({ maxRetriesPerRequest: 1, enableOfflineQueue: false });
    expect(consumer).toMatchObject({ maxRetriesPerRequest: null, enableOfflineQueue: true });
    expect(producer.password).toBe("pw");
    expect("username" in producer).toBe(false);
    expect("tls" in producer).toBe(false);
  });

  it("keeps TLS verification on for rediss://", () => {
    const options = redisConnectionOptions("rediss://redis.example.test:6380", "consumer");
    expect(options.tls).toEqual({ servername: "redis.example.test" });
  });
});

describe("redactRedisUrl", () => {
  it("masks the password", () => {
    expect(redactRedisUrl("redis://:hunter2@127.0.0.1:6379/0")).toBe(
      "redis://:***@127.0.0.1:6379/0",
    );
  });

  it("does not echo unparseable input", () => {
    expect(redactRedisUrl("hunter2")).toBe("<invalid REDIS_URL>");
  });
});
