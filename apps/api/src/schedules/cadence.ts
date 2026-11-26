/**
 * Schedule arithmetic, kept pure so every edge case is a unit test.
 *
 * A site's next run is stored as an absolute time (`sites.next_scan_at`),
 * not derived from "the last scan was N hours ago". That gives a fixed
 * cadence (no drift by one scheduler tick per run), makes "what is due?" a
 * single indexed range query, and gives the scheduler a value to
 * compare-and-set when it claims a run.
 */
import type { Schedule } from "../sites/store.js";

export type ActiveSchedule = Exclude<Schedule, "NONE">;

const HOUR_MS = 60 * 60 * 1000;

export const SCHEDULE_INTERVAL_MS: Readonly<Record<ActiveSchedule, number>> = Object.freeze({
  DAILY: 24 * HOUR_MS,
  WEEKLY: 7 * 24 * HOUR_MS,
});

function intervalOf(schedule: ActiveSchedule): number {
  switch (schedule) {
    case "DAILY":
      return SCHEDULE_INTERVAL_MS.DAILY;
    case "WEEKLY":
      return SCHEDULE_INTERVAL_MS.WEEKLY;
  }
}

export function isActiveSchedule(schedule: Schedule): schedule is ActiveSchedule {
  return schedule !== "NONE";
}

/**
 * The run after `due`. Normally exactly one interval later, which keeps the
 * cadence anchored. If the scheduler was down long enough that this is
 * already in the past, skip the missed runs and start a fresh interval from
 * `now`: one catch-up scan, not a burst of them.
 */
export function nextRunAfter(due: Date, schedule: ActiveSchedule, now: Date): Date {
  const interval = intervalOf(schedule);
  const next = due.getTime() + interval;
  return new Date(next > now.getTime() ? next : now.getTime() + interval);
}

/**
 * `next_scan_at` after the owner changes the schedule, or `undefined` to
 * leave it alone. Enabling or switching cadence makes the site due at once
 * (the owner sees a first result quickly, and a weekly→daily switch doesn't
 * wait out the old week). Re-sending the current schedule, as a client
 * saving the whole form does, changes nothing.
 */
export function nextScanAtForChange(
  current: Schedule,
  requested: Schedule,
  now: Date,
): Date | null | undefined {
  if (requested === current) return undefined;
  return isActiveSchedule(requested) ? now : null;
}
