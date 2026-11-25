/**
 * A real Redis for queue tests, bound to 127.0.0.1.
 *
 * - `TEST_REDIS_URL` set (CI's Redis service container): use it. Each test
 *   suite gets its own random key prefix, so suites never see each other's jobs.
 * - Otherwise start a throwaway `redis-server` on a free loopback port with a
 *   random password, no persistence, and stop it afterwards.
 *
 * If neither is available the suite fails with a message saying so. It does
 * not skip: a silently skipped queue test would let a broken queue pass CI.
 */
import { type ChildProcess, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer } from "node:net";

export interface TestRedis {
  readonly url: string;
  /** Unique per call; pass as the BullMQ `prefix`. */
  readonly prefix: string;
  stop(): Promise<void>;
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address !== null ? address.port : 0;
      server.close(() => {
        resolve(port);
      });
    });
  });
}

function waitForReady(child: ChildProcess): Promise<void> {
  return new Promise((resolve, reject) => {
    let output = "";
    const timer = setTimeout(() => {
      reject(new Error(`redis-server did not start:\n${output}`));
    }, 10_000);
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(
        new Error(
          `could not run redis-server (${error.message}). Install Redis or set TEST_REDIS_URL.`,
        ),
      );
    });
    child.stdout?.on("data", (chunk: Buffer) => {
      output += chunk.toString("utf8");
      if (output.includes("Ready to accept connections")) {
        clearTimeout(timer);
        resolve();
      }
    });
  });
}

export async function startTestRedis(): Promise<TestRedis> {
  const prefix = `test-${randomBytes(6).toString("hex")}`;
  const external = process.env.TEST_REDIS_URL;
  if (external !== undefined && external !== "") {
    const host = new URL(external).hostname;
    if (host !== "127.0.0.1" && host !== "localhost") {
      throw new Error("TEST_REDIS_URL must point at 127.0.0.1");
    }
    return { url: external, prefix, stop: () => Promise.resolve() };
  }
  const port = await freePort();
  const password = randomBytes(16).toString("hex");
  const child = spawn(
    "redis-server",
    [
      "--bind",
      "127.0.0.1",
      "--port",
      String(port),
      "--save",
      "",
      "--appendonly",
      "no",
      "--requirepass",
      password,
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  await waitForReady(child);
  return {
    url: `redis://:${password}@127.0.0.1:${String(port)}`,
    prefix,
    stop: () =>
      new Promise((resolve) => {
        if (child.exitCode !== null) {
          resolve();
          return;
        }
        child.once("exit", () => {
          resolve();
        });
        child.kill("SIGTERM");
      }),
  };
}
