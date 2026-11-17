// The blocking timer counts down from the server value with a monotonic clock
// (performance.now()). It never compares the browser wall clock with a server time.

/** Seconds left now. `startMs` and `nowMs` come from the same monotonic clock. */
export function remainingSeconds(initialSeconds: number, startMs: number, nowMs: number): number {
  const elapsed = Math.max(0, nowMs - startMs) / 1000;
  return Math.max(0, Math.ceil(initialSeconds - elapsed));
}

export interface TimerPreset {
  label: string;
  seconds: number;
}

export const TIMER_PRESETS: readonly TimerPreset[] = [
  { label: '30 s', seconds: 30 },
  { label: '5 min', seconds: 300 },
  { label: '1 h', seconds: 3600 },
];

/** The API accepts 1 to 86400 seconds (docs/API.md, section 4). */
export const MAX_TIMER_SECONDS = 86400;
