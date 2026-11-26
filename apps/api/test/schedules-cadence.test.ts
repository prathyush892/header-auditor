import { describe, expect, it } from "vitest";

import {
  isActiveSchedule,
  nextRunAfter,
  nextScanAtForChange,
  SCHEDULE_INTERVAL_MS,
} from "../src/schedules/cadence.js";

const DAY = 24 * 3_600_000;
const due = new Date("2026-11-25T09:00:00.000Z");

describe("nextRunAfter", () => {
  it("adds exactly one interval, so the cadence doesn't drift with the tick", () => {
    // The tick that ran it was 40 s late; the next run is still 09:00 tomorrow.
    const ranAt = new Date(due.getTime() + 40_000);
    expect(nextRunAfter(due, "DAILY", ranAt)).toEqual(new Date("2026-11-26T09:00:00.000Z"));
    expect(nextRunAfter(due, "WEEKLY", ranAt)).toEqual(new Date("2026-12-02T09:00:00.000Z"));
  });

  it("skips missed runs after an outage instead of bursting through them", () => {
    const afterOutage = new Date(due.getTime() + 3 * DAY + 5_000);
    expect(nextRunAfter(due, "DAILY", afterOutage)).toEqual(new Date(afterOutage.getTime() + DAY));
  });

  it("never returns a time at or before now", () => {
    const exactlyOneLate = new Date(due.getTime() + DAY);
    expect(nextRunAfter(due, "DAILY", exactlyOneLate).getTime()).toBeGreaterThan(
      exactlyOneLate.getTime(),
    );
  });

  it("uses 24 h and 7 d", () => {
    expect(SCHEDULE_INTERVAL_MS).toEqual({ DAILY: DAY, WEEKLY: 7 * DAY });
  });
});

describe("nextScanAtForChange", () => {
  const now = new Date("2026-11-25T12:00:00.000Z");

  it("makes a site due now when a schedule is enabled or switched", () => {
    expect(nextScanAtForChange("NONE", "DAILY", now)).toEqual(now);
    expect(nextScanAtForChange("WEEKLY", "DAILY", now)).toEqual(now);
  });

  it("clears the next run when scheduling is turned off", () => {
    expect(nextScanAtForChange("DAILY", "NONE", now)).toBeNull();
  });

  it("leaves it alone when the schedule is re-sent unchanged", () => {
    expect(nextScanAtForChange("DAILY", "DAILY", now)).toBeUndefined();
    expect(nextScanAtForChange("NONE", "NONE", now)).toBeUndefined();
  });

  it("knows which schedules are active", () => {
    expect(isActiveSchedule("NONE")).toBe(false);
    expect(isActiveSchedule("DAILY")).toBe(true);
  });
});
