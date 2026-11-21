import Fastify from "fastify";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ConfigError } from "../src/config.js";
import { createShutdown, start } from "../src/server.js";

describe("start (real socket on 127.0.0.1)", () => {
  let close: (() => Promise<void>) | undefined;

  afterEach(async () => {
    await close?.();
    close = undefined;
  });

  it("listens on an ephemeral loopback port and serves /health", async () => {
    const app = await start({
      env: { NODE_ENV: "test", LOG_LEVEL: "silent", API_HOST: "127.0.0.1", API_PORT: "0" },
      handleSignals: false,
    });
    close = () => app.close();
    const address = app.server.address();
    if (address === null || typeof address === "string") throw new Error("expected a TCP address");
    expect(address.address).toBe("127.0.0.1");
    const response = await fetch(`http://127.0.0.1:${String(address.port)}/health`);
    expect(response.status).toBe(200);
    expect(response.headers.get("x-request-id")).toBeTruthy();
    expect(await response.json()).toMatchObject({ status: "ok" });
  });

  it("refuses to start with invalid config", async () => {
    await expect(
      start({ env: { API_PORT: "not-a-port" }, handleSignals: false }),
    ).rejects.toBeInstanceOf(ConfigError);
  });
});

describe("createShutdown", () => {
  it("closes the app once and exits 0", async () => {
    const app = Fastify({ logger: false });
    const onClose = vi.fn();
    app.addHook("onClose", onClose);
    await app.ready();
    const exit = vi.fn();
    const shutdown = createShutdown(app, { timeoutMs: 1_000, exit });
    const first = shutdown("SIGTERM");
    const second = shutdown("SIGINT");
    expect(second).toBe(first);
    await first;
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(exit).toHaveBeenCalledExactlyOnceWith(0);
  });

  it("forces exit(1) when closing hangs past the timeout", async () => {
    vi.useFakeTimers();
    try {
      const app = Fastify({ logger: false });
      app.addHook("onClose", () => new Promise<void>(() => undefined));
      await app.ready();
      const exit = vi.fn();
      void createShutdown(app, { timeoutMs: 5_000, exit })("SIGTERM");
      await vi.advanceTimersByTimeAsync(4_999);
      expect(exit).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(1);
      expect(exit).toHaveBeenCalledExactlyOnceWith(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("exits 1 when an onClose hook fails", async () => {
    const app = Fastify({ logger: false });
    app.addHook("onClose", () => Promise.reject(new Error("pool close failed")));
    await app.ready();
    const exit = vi.fn();
    await createShutdown(app, { timeoutMs: 1_000, exit })("SIGTERM");
    expect(exit).toHaveBeenCalledExactlyOnceWith(1);
  });
});
