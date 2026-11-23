/**
 * Opaque pagination cursors for the newest-first site list.
 *
 * A cursor is base64url("<createdAt ms>.<id>"), the sort key of the last item
 * on the page. It is not signed, and doesn't need to be: every query is
 * already scoped to the signed-in owner, so a hand-crafted cursor can only
 * move to a different position in the caller's own list.
 */
import type { SiteCursor } from "./store.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const DECODED = /^(\d{1,15})\.([0-9a-f-]{36})$/;
/** Base64url of the longest valid payload is well under this. */
export const CURSOR_MAX_LENGTH = 128;

export function encodeCursor(cursor: SiteCursor): string {
  return Buffer.from(`${String(cursor.createdAt.getTime())}.${cursor.id}`, "utf8").toString(
    "base64url",
  );
}

/** Returns undefined for anything that isn't a cursor this API produced. */
export function decodeCursor(value: string): SiteCursor | undefined {
  if (value.length === 0 || value.length > CURSOR_MAX_LENGTH) return undefined;
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return undefined;
  const decoded = Buffer.from(value, "base64url").toString("utf8");
  // Node's decoder is lenient; insist on the canonical encoding.
  if (Buffer.from(decoded, "utf8").toString("base64url") !== value) return undefined;
  const match = DECODED.exec(decoded);
  if (match === null) return undefined;
  const [, msText = "", id = ""] = match;
  const ms = Number(msText);
  if (!Number.isSafeInteger(ms) || !UUID.test(id)) return undefined;
  const createdAt = new Date(ms);
  if (Number.isNaN(createdAt.getTime())) return undefined;
  return { createdAt, id };
}
