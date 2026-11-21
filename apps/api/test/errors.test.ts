import type { FastifyInstance } from "fastify";
import { afterEach, describe, expect, it } from "vitest";
import { z } from "zod";

import { AppError, classifyError, errorBody, INTERNAL_ERROR_MESSAGE } from "../src/errors.js";
import { createTestApp, type TestApp } from "./helpers/app.js";

describe("AppError", () => {
  it("keeps status, code, details and cause", () => {
    const cause = new Error("root");
    const error = new AppError(409, "SITE_EXISTS", "Site already added", {
      details: [{ path: "url", message: "duplicate" }],
      cause,
    });
    expect(error).toMatchObject({
      statusCode: 409,
      code: "SITE_EXISTS",
      message: "Site already added",
      name: "AppError",
    });
    expect(error.details).toEqual([{ path: "url", message: "duplicate" }]);
    expect(error.cause).toBe(cause);
  });

  it.each([200, 399, 600, 404.5, Number.NaN])("rejects status %s", (status) => {
    expect(() => new AppError(status, "X", "m")).toThrow(RangeError);
  });

  it.each(["lower", "HAS SPACE", "", "1START", "A".repeat(65)])("rejects code %j", (code) => {
    expect(() => new AppError(400, code, "m")).toThrow(RangeError);
  });
});

describe("classifyError", () => {
  it("maps ZodError to 400 with per-field details", () => {
    const result = z
      .object({ name: z.string(), nested: z.object({ n: z.number() }) })
      .safeParse({ nested: { n: "x" } });
    expect(result.success).toBe(false);
    const classified = classifyError(result.error);
    expect(classified).toMatchObject({
      statusCode: 400,
      code: "VALIDATION_FAILED",
      internal: false,
    });
    expect(classified.details?.map((d) => d.path)).toEqual(["name", "nested.n"]);
  });

  it("labels a root-level zod issue", () => {
    const result = z.string().safeParse(1);
    expect(classifyError(result.error).details?.[0]?.path).toBe("<root>");
  });

  it("exposes 4xx AppError messages", () => {
    expect(classifyError(new AppError(403, "FORBIDDEN", "Not your site"))).toEqual({
      statusCode: 403,
      code: "FORBIDDEN",
      message: "Not your site",
      internal: false,
    });
  });

  it("hides 5xx AppError messages", () => {
    expect(classifyError(new AppError(502, "UPSTREAM_FAILED", "db at 10.0.0.5 refused"))).toEqual({
      statusCode: 502,
      code: "UPSTREAM_FAILED",
      message: INTERNAL_ERROR_MESSAGE,
      internal: true,
    });
  });

  it("passes through framework 4xx errors with a status-derived code", () => {
    const error = Object.assign(new Error("Request body is too large"), { statusCode: 413 });
    expect(classifyError(error)).toMatchObject({
      statusCode: 413,
      code: "PAYLOAD_TOO_LARGE",
      internal: false,
    });
    const unusual = Object.assign(new Error("teapot"), { statusCode: 418 });
    expect(classifyError(unusual).code).toBe("BAD_REQUEST");
  });

  it.each([
    ["plain Error", new Error("password=hunter2 at db.internal")],
    ["Error with 500 status", Object.assign(new Error("boom"), { statusCode: 500 })],
    ["Error with bogus status", Object.assign(new Error("boom"), { statusCode: 200 })],
    ["string", "oops"],
    ["null", null],
    ["undefined", undefined],
    ["object with statusCode but not an Error", { statusCode: 400, message: "fake" }],
  ])("treats %s as an internal 500", (_label, value) => {
    expect(classifyError(value)).toEqual({
      statusCode: 500,
      code: "INTERNAL_ERROR",
      message: INTERNAL_ERROR_MESSAGE,
      internal: true,
    });
  });

  it("builds the envelope without an empty details key", () => {
    expect(
      errorBody({ statusCode: 404, code: "NOT_FOUND", message: "m", internal: false }, "r1"),
    ).toEqual({
      error: { code: "NOT_FOUND", message: "m", requestId: "r1" },
    });
  });
});

describe("error handler (in-memory app)", () => {
  let ctx: TestApp | undefined;

  afterEach(async () => {
    await ctx?.app.close();
    ctx = undefined;
  });

  async function app(setup: (app: FastifyInstance) => void): Promise<TestApp> {
    ctx = await createTestApp({ setup, env: { API_BODY_LIMIT_BYTES: "1024" } });
    return ctx;
  }

  it("returns 400 with details when a handler's zod parse fails", async () => {
    const { app: server } = await app((s) => {
      s.post("/echo", (request) =>
        z.object({ email: z.email(), age: z.number().int() }).parse(request.body),
      );
    });
    const response = await server.inject({
      method: "POST",
      url: "/echo",
      payload: { email: "nope", age: 1.5 },
    });
    expect(response.statusCode).toBe(400);
    expect(response.headers["content-type"]).toBe("application/json; charset=utf-8");
    const body = response.json<{
      error: { code: string; details: { path: string }[]; requestId: string };
    }>();
    expect(body.error.code).toBe("VALIDATION_FAILED");
    expect(body.error.details.map((d) => d.path)).toEqual(["email", "age"]);
    expect(body.error.requestId).toBe(response.headers["x-request-id"]);
  });

  it("maps Fastify JSON-schema validation to the same shape", async () => {
    const { app: server } = await app((s) => {
      s.post(
        "/typed",
        {
          schema: {
            body: {
              type: "object",
              required: ["name"],
              properties: { name: { type: "string", minLength: 1 } },
              additionalProperties: false,
            },
          },
        },
        () => ({ ok: true }),
      );
    });
    const response = await server.inject({ method: "POST", url: "/typed", payload: { name: "" } });
    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: { code: "VALIDATION_FAILED", details: [{ path: "name" }] },
    });
  });

  it("returns AppError 4xx as-is", async () => {
    const { app: server } = await app((s) => {
      s.get("/conflict", () => {
        throw new AppError(409, "SITE_EXISTS", "Site already added");
      });
    });
    const response = await server.inject("/conflict");
    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({
      error: { code: "SITE_EXISTS", message: "Site already added" },
    });
  });

  it("hides unexpected errors from the client but logs them under the same request id", async () => {
    const { app: server, logs } = await app((s) => {
      s.get("/crash", async () => {
        await Promise.resolve();
        throw new Error("connect ECONNREFUSED 10.1.2.3:5432");
      });
    });
    const response = await server.inject({
      url: "/crash",
      headers: { "x-request-id": "trace-123" },
    });
    expect(response.statusCode).toBe(500);
    expect(response.body).not.toContain("ECONNREFUSED");
    expect(response.body).not.toContain("at ");
    expect(response.json()).toEqual({
      error: { code: "INTERNAL_ERROR", message: INTERNAL_ERROR_MESSAGE, requestId: "trace-123" },
    });
    const errorLine = logs.lines.find((line) => line.msg === "request failed");
    expect(errorLine).toMatchObject({ level: 50, reqId: "trace-123" });
    expect(JSON.stringify(errorLine)).toContain("ECONNREFUSED");
    expect(JSON.stringify(errorLine)).toContain("stack");
  });

  it("handles non-Error throws", async () => {
    const { app: server } = await app((s) => {
      s.get("/throw-string", () => {
        // eslint-disable-next-line @typescript-eslint/only-throw-error -- testing hostile input
        throw "raw string";
      });
    });
    const response = await server.inject("/throw-string");
    expect(response.statusCode).toBe(500);
    expect(response.body).not.toContain("raw string");
  });

  it("logs client errors at info, not error", async () => {
    const { app: server, logs } = await app((s) => {
      s.get("/forbidden", () => {
        throw new AppError(403, "FORBIDDEN", "no");
      });
    });
    await server.inject("/forbidden");
    expect(logs.lines.some((l) => l.level === 50)).toBe(false);
    expect(logs.lines.find((l) => l.msg === "client error")).toMatchObject({
      level: 30,
      code: "FORBIDDEN",
    });
  });

  it("answers malformed JSON with 400", async () => {
    const { app: server } = await app((s) => {
      s.post("/json", () => ({ ok: true }));
    });
    const response = await server.inject({
      method: "POST",
      url: "/json",
      headers: { "content-type": "application/json" },
      payload: '{"a":',
    });
    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: { code: "BAD_REQUEST" } });
  });

  it("rejects prototype-pollution keys in JSON bodies", async () => {
    const { app: server } = await app((s) => {
      s.post("/json", () => ({ ok: true }));
    });
    const response = await server.inject({
      method: "POST",
      url: "/json",
      headers: { "content-type": "application/json" },
      payload: '{"__proto__":{"admin":true}}',
    });
    expect(response.statusCode).toBe(400);
  });

  it("enforces the configured body limit with 413", async () => {
    const { app: server } = await app((s) => {
      s.post("/json", () => ({ ok: true }));
    });
    const response = await server.inject({
      method: "POST",
      url: "/json",
      payload: { blob: "x".repeat(2048) },
    });
    expect(response.statusCode).toBe(413);
    expect(response.json()).toMatchObject({ error: { code: "PAYLOAD_TOO_LARGE" } });
  });

  it("returns 415 for unsupported content types", async () => {
    const { app: server } = await app((s) => {
      s.post("/json", () => ({ ok: true }));
    });
    const response = await server.inject({
      method: "POST",
      url: "/json",
      headers: { "content-type": "application/xml" },
      payload: "<a/>",
    });
    expect(response.statusCode).toBe(415);
    expect(response.json()).toMatchObject({ error: { code: "UNSUPPORTED_MEDIA_TYPE" } });
  });

  it("returns a JSON 404 that does not reflect the requested path", async () => {
    const { app: server } = await app(() => undefined);
    const response = await server.inject("/%3Cscript%3Ealert(1)%3C%2Fscript%3E?q=<b>");
    expect(response.statusCode).toBe(404);
    expect(response.headers["content-type"]).toBe("application/json; charset=utf-8");
    expect(response.body).not.toMatch(/script|<b>/i);
    expect(response.json()).toMatchObject({
      error: { code: "NOT_FOUND", message: "Route not found" },
    });
  });
});
