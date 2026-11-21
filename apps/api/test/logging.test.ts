import type { IncomingMessage } from "node:http";

import { afterEach, describe, expect, it } from "vitest";

import { BASELINE_HEADERS } from "../src/app.js";
import { generateRequestId, REDACTED, serializeRequest, stripQuery } from "../src/logger.js";
import { createTestApp, type TestApp } from "./helpers/app.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function fakeRequest(headers: IncomingMessage["headers"]): IncomingMessage {
  return { headers } as IncomingMessage;
}

describe("generateRequestId", () => {
  it("reuses a safe caller-supplied id", () => {
    expect(generateRequestId(fakeRequest({ "x-request-id": "edge-01:abc.DEF_9" }))).toBe(
      "edge-01:abc.DEF_9",
    );
  });

  it("uses the first value when the header repeats", () => {
    expect(generateRequestId(fakeRequest({ "x-request-id": ["first", "second"] }))).toBe("first");
  });

  it.each([
    ["missing", undefined],
    ["empty", ""],
    ["newline injection", 'abc\n{"level":60,"msg":"forged"}'],
    ["spaces", "a b"],
    ["too long", "a".repeat(65)],
    ["html", "<script>"],
  ])("generates a UUID when the header is %s", (_label, value) => {
    const id = generateRequestId(fakeRequest(value === undefined ? {} : { "x-request-id": value }));
    expect(id).toMatch(UUID);
  });

  it("generates unique ids", () => {
    const ids = new Set(Array.from({ length: 50 }, () => generateRequestId(fakeRequest({}))));
    expect(ids.size).toBe(50);
  });
});

describe("stripQuery / serializeRequest", () => {
  it.each([
    ["/reset?token=abc", "/reset"],
    ["/a#frag", "/a"],
    ["/a?b#c", "/a"],
    ["/plain", "/plain"],
    [undefined, ""],
  ])("stripQuery(%j) = %j", (input, expected) => {
    expect(stripQuery(input)).toBe(expected);
  });

  it("logs method, path and address only", () => {
    expect(serializeRequest({ method: "GET", url: "/x?secret=1", ip: "127.0.0.1" })).toEqual({
      method: "GET",
      url: "/x",
      remoteAddress: "127.0.0.1",
    });
  });
});

describe("request logging and headers (in-memory app)", () => {
  let ctx: TestApp | undefined;

  afterEach(async () => {
    await ctx?.app.close();
    ctx = undefined;
  });

  it("echoes the request id and sets baseline security headers", async () => {
    ctx = await createTestApp();
    const response = await ctx.app.inject({
      url: "/health",
      headers: { "x-request-id": "abc-123" },
    });
    expect(response.headers["x-request-id"]).toBe("abc-123");
    expect(response.headers).toMatchObject(BASELINE_HEADERS);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.headers["x-powered-by"]).toBeUndefined();
    expect(response.headers.server).toBeUndefined();
  });

  it("sets the same headers on error responses", async () => {
    ctx = await createTestApp();
    const response = await ctx.app.inject("/nope");
    expect(response.statusCode).toBe(404);
    expect(response.headers["x-content-type-options"]).toBe("nosniff");
    expect(response.headers["x-request-id"]).toMatch(UUID);
  });

  it("writes structured JSON lines with request id, service and ISO time", async () => {
    ctx = await createTestApp();
    await ctx.app.inject({
      url: "/health?token=supersecret",
      headers: { "x-request-id": "log-test" },
    });
    const incoming = ctx.logs.lines.find((line) => line.msg === "incoming request");
    const completed = ctx.logs.lines.find((line) => line.msg === "request completed");
    expect(incoming).toMatchObject({
      reqId: "log-test",
      service: "api",
      req: { method: "GET", url: "/health" },
    });
    expect(completed).toMatchObject({ reqId: "log-test", res: { statusCode: 200 } });
    expect(new Date(String(incoming?.time)).toISOString()).toBe(incoming?.time);
    expect(ctx.logs.text()).not.toContain("supersecret");
  });

  it("never logs credentials sent in headers", async () => {
    ctx = await createTestApp({
      setup: (app) => {
        app.get("/dump", (request) => {
          // A careless future route logging the raw headers must still be safe.
          request.log.info({ req: { headers: request.headers } }, "headers dump");
          return { ok: true };
        });
      },
    });
    await ctx.app.inject({
      url: "/dump",
      headers: {
        authorization: "Bearer tok-SECRET-1",
        cookie: "sid=SECRET-2",
        "x-api-key": "SECRET-3",
      },
    });
    const text = ctx.logs.text();
    expect(text).not.toMatch(/SECRET-\d/);
  });

  it("redacts password/token/secret fields in logged objects", async () => {
    ctx = await createTestApp({
      setup: (app) => {
        app.post("/login", (request) => {
          request.log.info({ body: request.body }, "login attempt");
          return { ok: true };
        });
      },
    });
    await ctx.app.inject({
      method: "POST",
      url: "/login",
      payload: { email: "a@example.test", password: "hunter2", token: "t0k", secret: "s3c" },
    });
    const line = ctx.logs.lines.find((l) => l.msg === "login attempt");
    expect(line).toMatchObject({
      body: { email: "a@example.test", password: REDACTED, token: REDACTED, secret: REDACTED },
    });
    expect(ctx.logs.text()).not.toMatch(/hunter2|t0k|s3c/);
  });

  it("respects LOG_LEVEL", async () => {
    ctx = await createTestApp({ env: { LOG_LEVEL: "warn" } });
    await ctx.app.inject("/health");
    expect(ctx.logs.lines).toEqual([]);
  });
});
