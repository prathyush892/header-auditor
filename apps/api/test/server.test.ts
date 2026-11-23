import Fastify from "fastify";
import { afterEach, describe, expect, it, vi } from "vitest";

import { MemoryAuthStore } from "../src/auth/store.js";
import { ConfigError } from "../src/config.js";
import { createShutdown, start } from "../src/server.js";
import { fastHasher } from "./helpers/auth.js";

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

  it("round-trips the session cookie over a real HTTP connection", async () => {
    const app = await start({
      env: { NODE_ENV: "test", LOG_LEVEL: "silent", API_PORT: "0", AUTH_COOKIE_SECURE: "false" },
      handleSignals: false,
      auth: { store: new MemoryAuthStore(), hasher: fastHasher(), pruneIntervalMs: 0 },
    });
    close = () => app.close();
    const address = app.server.address();
    if (address === null || typeof address === "string") throw new Error("expected a TCP address");
    const base = `http://127.0.0.1:${String(address.port)}`;

    const registered = await fetch(`${base}/auth/register`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: "http://localhost:3000" },
      body: JSON.stringify({ email: "socket@example.test", password: "a long enough passphrase" }),
    });
    expect(registered.status).toBe(201);
    const cookie = registered.headers.getSetCookie()[0]?.split(";")[0] ?? "";
    expect(cookie).toMatch(/^ha_session=/);

    const session = await fetch(`${base}/auth/session`, { headers: { cookie } });
    expect(session.status).toBe(200);
    expect(await session.json()).toMatchObject({ user: { email: "socket@example.test" } });
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
