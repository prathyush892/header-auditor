/**
 * The processor's decisions, with an in-memory store and a fake engine: what
 * gets claimed, what is a result versus a retry, and how leases fence writes.
 */
import { ScanJobDataError } from "@header-auditor/queue";
import { describe, expect, it } from "vitest";

import { FAILURE_MESSAGES, TargetError } from "../src/engine.js";
import { createScanProcessor, type RunEngine } from "../src/processor.js";
import { INTERNAL_FAILURE_MESSAGE, MemoryWorkerScanStore } from "../src/store.js";
import { fakeResult, SCAN_ID, TestLogger } from "./helpers/fixtures.js";

const STALE_MS = 300_000;
const T0 = Date.parse("2026-11-24T12:00:00.000Z");

function setup(run: RunEngine, start = T0) {
  let ms = start;
  const store = new MemoryWorkerScanStore();
  const logger = new TestLogger();
  const calls: { target: string; firstPartyHosts: readonly string[] }[] = [];
  const process = createScanProcessor({
    store,
    logger,
    engine: { timeoutMs: 5_000, allowPrivate: false },
    staleAfterMs: STALE_MS,
    now: () => new Date(ms),
    run: (target, options) => {
      calls.push({ target, firstPartyHosts: options.firstPartyHosts });
      ms += 1_500; // the scan takes 1.5 s
      return run(target, options);
    },
  });
  return {
    store,
    logger,
    calls,
    process,
    advance: (delta: number) => {
      ms += delta;
    },
  };
}

const succeed: RunEngine = () => Promise.resolve(fakeResult());

describe("createScanProcessor", () => {
  it("claims a queued scan, runs the engine on the stored URL and saves the result", async () => {
    const t = setup(succeed);
    t.store.add({
      id: SCAN_ID,
      requestedUrl: "https://shop.example.com",
      firstPartyHosts: ["cdn.shop.example.com"],
    });

    expect(await t.process({ scanId: SCAN_ID })).toBe("succeeded");

    expect(t.calls).toEqual([
      { target: "https://shop.example.com", firstPartyHosts: ["cdn.shop.example.com"] },
    ]);
    const scan = t.store.scans.get(SCAN_ID);
    expect(scan?.status).toBe("SUCCEEDED");
    expect(scan?.startedAt?.getTime()).toBe(T0);
    expect(scan?.finishedAt?.getTime()).toBe(T0 + 1_500);
    expect(scan?.result).toMatchObject({ httpStatus: 200, engineVersion: "0.0.0" });
    expect(scan?.result?.grade).toMatch(/^[A-F]$/);
    // Header findings first, then content; positions run across sections.
    const findings = scan?.result?.findings ?? [];
    expect(findings[0]).toMatchObject({ category: "HEADERS", position: 0 });
    expect(findings.at(-1)?.category).toBe("CONTENT");
    expect(findings.map((f) => f.position)).toEqual(findings.map((_, i) => i));
  });

  it("strips NUL characters from the stored report (jsonb rejects them)", async () => {
    // Header values can't hold NUL, but body-derived strings can.
    const t = setup(() =>
      Promise.resolve({
        ...fakeResult(),
        redirects: [
          {
            url: "https://shop.example.com/",
            statusCode: 301,
            location: "https://shop\u0000.example.com/x",
          },
        ],
      }),
    );
    t.store.add({ id: SCAN_ID, requestedUrl: "https://shop.example.com" });
    expect(await t.process({ scanId: SCAN_ID })).toBe("succeeded");
    const stored = JSON.stringify(t.store.scans.get(SCAN_ID)?.result?.report);
    expect(stored).toContain("https://shop.example.com/x");
    expect(stored).not.toContain("\\u0000");
  });

  it("saves a target failure as a FAILED result with the fixed message, without retrying", async () => {
    const t = setup(() =>
      Promise.reject(new TargetError("BLOCKED_ADDRESS", FAILURE_MESSAGES.BLOCKED_ADDRESS)),
    );
    t.store.add({ id: SCAN_ID, requestedUrl: "https://rebind.example.com" });

    expect(await t.process({ scanId: SCAN_ID })).toBe("failed");
    expect(t.store.scans.get(SCAN_ID)).toMatchObject({
      status: "FAILED",
      error: FAILURE_MESSAGES.BLOCKED_ADDRESS,
    });
    expect(t.logger.entries.filter((e) => e.level === "error")).toEqual([]);
  });

  it("saves an engine bug as an internal failure and logs it, never storing the error text", async () => {
    const t = setup(() => Promise.reject(new TypeError("cannot read 'x' of undefined at /app")));
    t.store.add({ id: SCAN_ID, requestedUrl: "https://shop.example.com" });

    expect(await t.process({ scanId: SCAN_ID })).toBe("failed");
    expect(t.store.scans.get(SCAN_ID)?.error).toBe(INTERNAL_FAILURE_MESSAGE);
    expect(t.logger.entries.find((e) => e.level === "error")?.message).toBe("scan engine error");
  });

  it.each(["SUCCEEDED", "FAILED"] as const)("skips a scan that is already %s", async (status) => {
    const t = setup(succeed);
    t.store.add({ id: SCAN_ID, requestedUrl: "https://shop.example.com", status });
    expect(await t.process({ scanId: SCAN_ID })).toBe("skipped");
    expect(t.calls).toEqual([]);
  });

  it("skips a scan that no longer exists (its site was deleted)", async () => {
    const t = setup(succeed);
    expect(await t.process({ scanId: SCAN_ID })).toBe("skipped");
  });

  it("skips a RUNNING scan held by a live worker, but re-claims a stale one", async () => {
    const t = setup(succeed);
    t.store.add({
      id: SCAN_ID,
      requestedUrl: "https://shop.example.com",
      status: "RUNNING",
      startedAt: new Date(T0 - 60_000),
    });
    expect(await t.process({ scanId: SCAN_ID })).toBe("skipped");

    t.advance(STALE_MS);
    expect(await t.process({ scanId: SCAN_ID })).toBe("succeeded");
  });

  it("does not let a worker whose lease was taken over overwrite the newer run", async () => {
    // Worker A claims, then stalls long enough that worker B re-claims and finishes.
    let releaseA: () => void = () => undefined;
    const store = new MemoryWorkerScanStore();
    store.add({ id: SCAN_ID, requestedUrl: "https://shop.example.com" });
    let ms = T0;
    const base = {
      store,
      logger: new TestLogger(),
      engine: { timeoutMs: 5_000, allowPrivate: false },
      staleAfterMs: STALE_MS,
      now: () => new Date(ms),
    };
    const workerA = createScanProcessor({
      ...base,
      run: () =>
        new Promise((resolve) => {
          releaseA = () => {
            resolve(fakeResult("https://a.example.com/"));
          };
        }),
    });
    const workerB = createScanProcessor({
      ...base,
      run: () => Promise.resolve(fakeResult("https://b.example.com/")),
    });

    const a = workerA({ scanId: SCAN_ID });
    await Promise.resolve();
    ms += STALE_MS + 1;
    expect(await workerB({ scanId: SCAN_ID })).toBe("succeeded");
    releaseA();
    expect(await a).toBe("lease_lost");
    expect(store.scans.get(SCAN_ID)?.result?.finalUrl).toBe("https://b.example.com/");
  });

  it("hands the scan back (QUEUED) and rethrows when saving fails, so a retry can run it", async () => {
    const t = setup(succeed);
    t.store.add({ id: SCAN_ID, requestedUrl: "https://shop.example.com" });
    const original = t.store.completeScan.bind(t.store);
    t.store.completeScan = () => Promise.reject(new Error("connection terminated"));

    await expect(t.process({ scanId: SCAN_ID })).rejects.toThrow("connection terminated");
    expect(t.store.scans.get(SCAN_ID)).toMatchObject({ status: "QUEUED", startedAt: null });

    t.store.completeScan = original;
    expect(await t.process({ scanId: SCAN_ID })).toBe("succeeded");
  });

  it("still rethrows the original error when releasing fails too", async () => {
    const t = setup(succeed);
    t.store.add({ id: SCAN_ID, requestedUrl: "https://shop.example.com" });
    t.store.completeScan = () => Promise.reject(new Error("database down"));
    t.store.releaseScan = () => Promise.reject(new Error("still down"));
    await expect(t.process({ scanId: SCAN_ID })).rejects.toThrow("database down");
    expect(t.logger.messages()).toContain("could not release scan");
  });

  it.each([
    ["no payload", undefined],
    ["an injected URL", { scanId: SCAN_ID, url: "http://169.254.169.254/" }],
    ["a bad id", { scanId: "1 OR 1=1" }],
  ])("rejects %s before touching the store", async (_label, data) => {
    const t = setup(succeed);
    t.store.add({ id: SCAN_ID, requestedUrl: "https://shop.example.com" });
    await expect(t.process(data)).rejects.toThrow(ScanJobDataError);
    expect(t.store.scans.get(SCAN_ID)?.status).toBe("QUEUED");
  });

  it("passes the job's abort signal to the engine", async () => {
    let seen: AbortSignal | undefined;
    const t = setup((_target, options) => {
      seen = options.signal;
      return Promise.resolve(fakeResult());
    });
    t.store.add({ id: SCAN_ID, requestedUrl: "https://shop.example.com" });
    const controller = new AbortController();
    await t.process({ scanId: SCAN_ID }, controller.signal);
    expect(seen).toBe(controller.signal);
  });
});
