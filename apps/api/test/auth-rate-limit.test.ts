import { describe, expect, it } from "vitest";

import { MemoryRateLimiter } from "../src/auth/rate-limit.js";

function limiter(maxKeys?: number) {
  let now = 1_000_000;
  const instance = new MemoryRateLimiter({
    windowMs: 60_000,
    now: () => now,
    ...(maxKeys === undefined ? {} : { maxKeys }),
  });
  return { instance, advance: (ms: number) => (now += ms) };
}

describe("MemoryRateLimiter", () => {
  it("allows `limit` attempts per window, then blocks with a retry hint", async () => {
    const { instance, advance } = limiter();
    for (let i = 3; i > 0; i -= 1) {
      expect(await instance.consume("k", 3)).toEqual({
        allowed: true,
        remaining: i - 1,
        retryAfterMs: 60_000,
      });
    }
    advance(15_000);
    expect(await instance.consume("k", 3)).toEqual({
      allowed: false,
      remaining: 0,
      retryAfterMs: 45_000,
    });
  });

  it("opens a new window once the old one ends", async () => {
    const { instance, advance } = limiter();
    for (let i = 0; i < 5; i += 1) await instance.consume("k", 2);
    advance(60_000);
    expect((await instance.consume("k", 2)).allowed).toBe(true);
  });

  it("counts keys independently and reset() clears one key", async () => {
    const { instance } = limiter();
    await instance.consume("a", 1);
    expect((await instance.consume("a", 1)).allowed).toBe(false);
    expect((await instance.consume("b", 1)).allowed).toBe(true);
    await instance.reset("a");
    expect((await instance.consume("a", 1)).allowed).toBe(true);
  });

  it("keeps blocking during a sustained attack without growing the counter", async () => {
    const { instance } = limiter();
    for (let i = 0; i < 10_000; i += 1) await instance.consume("k", 5);
    expect((await instance.consume("k", 5)).allowed).toBe(false);
  });

  it("bounds memory: evicts expired keys first, then the oldest", async () => {
    const { instance, advance } = limiter(3);
    await instance.consume("old", 1);
    advance(61_000);
    await instance.consume("a", 1);
    await instance.consume("b", 1);
    await instance.consume("c", 1); // full: evicts expired "old"
    expect(instance.size).toBe(3);
    await instance.consume("d", 1); // full, none expired: evicts "a"
    expect(instance.size).toBe(3);
    expect((await instance.consume("a", 1)).allowed).toBe(true);
    // "c" is still tracked and blocked.
    expect((await instance.consume("c", 1)).allowed).toBe(false);
  });

  it.each([0, -1, 1.5])("rejects windowMs=%s", (windowMs) => {
    expect(() => new MemoryRateLimiter({ windowMs })).toThrow(RangeError);
  });

  it("rejects a non-positive limit", async () => {
    const { instance } = limiter();
    expect(() => instance.consume("k", 0)).toThrow(RangeError);
    await expect(instance.consume("k", 1)).resolves.toMatchObject({ allowed: true });
  });
});
