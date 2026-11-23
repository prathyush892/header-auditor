import { describe, expect, it } from "vitest";

import { CURSOR_MAX_LENGTH, decodeCursor, encodeCursor } from "../src/sites/cursor.js";
import { compareNewestFirst } from "../src/sites/store.js";

const ID = "0b7c6f0e-3f1a-4c2d-9e8f-1a2b3c4d5e6f";

describe("site cursors", () => {
  it("round-trips the sort key", () => {
    const cursor = { createdAt: new Date("2026-11-23T10:00:00.123Z"), id: ID };
    const encoded = encodeCursor(cursor);
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(encoded.length).toBeLessThan(CURSOR_MAX_LENGTH);
    expect(decodeCursor(encoded)).toEqual(cursor);
  });

  const b64 = (text: string): string => Buffer.from(text).toString("base64url");

  it.each([
    ["empty", ""],
    ["not base64url", "abc+/="],
    ["too long", "a".repeat(CURSOR_MAX_LENGTH + 1)],
    ["no separator", b64(`1700000000000${ID}`)],
    ["upper-case id", b64(`1700000000000.${ID.toUpperCase()}`)],
    ["not a uuid", b64("1700000000000.not-a-uuid-not-a-uuid-not-a-uuid-xxxx")],
    ["negative time", b64(`-1.${ID}`)],
    ["huge time", b64(`9999999999999999.${ID}`)],
    ["trailing data", b64(`1700000000000.${ID}.x`)],
    ["SQL-looking payload", b64("1' OR '1'='1")],
  ])("rejects %s", (_label, value) => {
    expect(decodeCursor(value)).toBeUndefined();
  });

  it("rejects non-canonical base64url", () => {
    const encoded = encodeCursor({ createdAt: new Date(1_700_000_000_000), id: ID });
    // Same bytes, but with padding: Node would decode it, the API refuses it.
    expect(decodeCursor(`${encoded}=`)).toBeUndefined();
  });
});

describe("compareNewestFirst", () => {
  it("orders by createdAt desc, then id desc", () => {
    const t1 = new Date(1_000);
    const t2 = new Date(2_000);
    const rows = [
      { createdAt: t1, id: "a" },
      { createdAt: t2, id: "a" },
      { createdAt: t1, id: "b" },
    ];
    expect(rows.sort(compareNewestFirst)).toEqual([
      { createdAt: t2, id: "a" },
      { createdAt: t1, id: "b" },
      { createdAt: t1, id: "a" },
    ]);
    const same = { createdAt: t1, id: "a" };
    expect(compareNewestFirst(same, { ...same })).toBe(0);
  });
});
