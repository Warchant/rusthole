// Background polls and the idle limit of the session (review item m17).
//
// Each API request moves the idle limit of the session on the server (1 h, docs/API.md
// 3.1). A poll that runs with no end keeps a session alive until the absolute limit.
// The rule: a poll runs only while the tab is visible and the user gave an input in the
// last POLL_IDLE_LIMIT_MS. When the user comes back (an input, or the tab becomes
// visible), each stopped poll runs one time at once and then at its normal interval.
//
// The policy (`mayPoll`) is a pure function with `now` as input. The shell
// (`createActivity`, `poll`) holds the listeners and the timers.

/** Polls stop after this time with no user input. It is much shorter than the 1 h idle limit. */
export const POLL_IDLE_LIMIT_MS = 15 * 60_000;

/** The events that count as user input. */
export const INPUT_EVENTS = ['pointerdown', 'pointermove', 'keydown', 'wheel', 'touchstart'] as const;

export interface ActivityFacts {
  /** True while the tab is hidden. */
  hidden: boolean;
  /** Monotonic time (ms) of the last user input. */
  lastInputMs: number;
  /** Monotonic time (ms) now. */
  nowMs: number;
}

/** True when a background poll can send a request now. */
export function mayPoll(f: ActivityFacts, idleLimitMs = POLL_IDLE_LIMIT_MS): boolean {
  if (f.hidden) return false;
  // A clock that goes back (it must not, but be safe) counts as a new input.
  const idle = Math.max(0, f.nowMs - f.lastInputMs);
  return idle < idleLimitMs;
}

export interface Activity {
  /** True when a background poll can send a request now. */
  mayPoll(): boolean;
  /** Calls `fn` on each user input and each change to a visible tab. Returns the unsubscribe function. */
  onWake(fn: () => void): () => void;
  /** Removes the listeners. */
  stop(): void;
}

/**
 * Follows user input and the visibility of the tab. `now` must be a monotonic clock
 * (performance.now), because the wall clock can jump.
 */
export function createActivity(
  doc: Document,
  now: () => number = () => performance.now(),
  idleLimitMs = POLL_IDLE_LIMIT_MS,
): Activity {
  let lastInputMs = now();
  const wakers = new Set<() => void>();
  const wake = () => {
    for (const fn of [...wakers]) fn();
  };
  const onInput = () => {
    const wasIdle = !mayPoll({ hidden: false, lastInputMs, nowMs: now() }, idleLimitMs);
    lastInputMs = now();
    // pointermove comes very often: wake the polls only when they stopped.
    if (wasIdle) wake();
  };
  const onVisibility = () => {
    if (doc.visibilityState === 'visible') {
      lastInputMs = now();
      wake();
    }
  };
  for (const type of INPUT_EVENTS) doc.addEventListener(type, onInput, { capture: true, passive: true });
  doc.addEventListener('visibilitychange', onVisibility);
  return {
    mayPoll: () => mayPoll({ hidden: doc.visibilityState === 'hidden', lastInputMs, nowMs: now() }, idleLimitMs),
    onWake(fn) {
      wakers.add(fn);
      return () => wakers.delete(fn);
    },
    stop() {
      for (const type of INPUT_EVENTS) doc.removeEventListener(type, onInput, { capture: true });
      doc.removeEventListener('visibilitychange', onVisibility);
      wakers.clear();
    },
  };
}

let shared: Activity | null = null;

/** The activity of this page. It starts at the first use. */
export function pageActivity(): Activity {
  shared ??= createActivity(document);
  return shared;
}

/** Stops the shared activity. For tests. */
export function resetPageActivity(): void {
  shared?.stop();
  shared = null;
}

/**
 * Calls `fn` each `intervalMs` while `activity.mayPoll()` is true. A tick that is
 * skipped marks the poll as late; the next wake (input or visible tab) then calls `fn`
 * one time at once. Returns the stop function: it clears the timer and the listener.
 */
export function poll(fn: () => void, intervalMs: number, activity: Activity = pageActivity()): () => void {
  let late = false;
  const timer = setInterval(() => {
    if (activity.mayPoll()) {
      late = false;
      fn();
    } else {
      late = true;
    }
  }, intervalMs);
  const unsubscribe = activity.onWake(() => {
    if (late && activity.mayPoll()) {
      late = false;
      fn();
    }
  });
  return () => {
    clearInterval(timer);
    unsubscribe();
  };
}
