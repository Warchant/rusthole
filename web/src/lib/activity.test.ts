import { afterEach, describe, expect, it, vi } from 'vitest';
import { createActivity, INPUT_EVENTS, mayPoll, poll, POLL_IDLE_LIMIT_MS } from './activity';

/** A document with only the parts that createActivity uses. */
class FakeDoc extends EventTarget {
  visibilityState: DocumentVisibilityState = 'visible';
  listeners = 0;
  override addEventListener(...args: Parameters<EventTarget['addEventListener']>) {
    this.listeners += 1;
    super.addEventListener(...args);
  }
  override removeEventListener(...args: Parameters<EventTarget['removeEventListener']>) {
    this.listeners -= 1;
    super.removeEventListener(...args);
  }
  setVisible(visible: boolean) {
    this.visibilityState = visible ? 'visible' : 'hidden';
    this.dispatchEvent(new Event('visibilitychange'));
  }
}

function setup() {
  let now = 1000;
  const doc = new FakeDoc();
  const activity = createActivity(doc as unknown as Document, () => now);
  return {
    doc,
    activity,
    advance(ms: number) {
      now += ms;
    },
  };
}

afterEach(() => vi.useRealTimers());

describe('mayPoll', () => {
  it('allows a poll only while visible and before the idle limit', () => {
    expect(mayPoll({ hidden: false, lastInputMs: 0, nowMs: 0 })).toBe(true);
    expect(mayPoll({ hidden: false, lastInputMs: 0, nowMs: POLL_IDLE_LIMIT_MS - 1 })).toBe(true);
    expect(mayPoll({ hidden: false, lastInputMs: 0, nowMs: POLL_IDLE_LIMIT_MS })).toBe(false);
    expect(mayPoll({ hidden: true, lastInputMs: 0, nowMs: 0 })).toBe(false);
    // A clock that goes back does not stop the polls.
    expect(mayPoll({ hidden: false, lastInputMs: 5000, nowMs: 0 })).toBe(true);
  });

  it('keeps the limit far below the 1 h idle limit of the server', () => {
    expect(POLL_IDLE_LIMIT_MS).toBeLessThanOrEqual(30 * 60_000);
  });

  it('property: a poll is allowed exactly when visible and idle < limit', () => {
    for (let i = 0; i < 2000; i++) {
      const last = Math.floor(Math.random() * 1e7);
      const now = last + Math.floor(Math.random() * 2 * POLL_IDLE_LIMIT_MS);
      const hidden = Math.random() < 0.3;
      expect(mayPoll({ hidden, lastInputMs: last, nowMs: now })).toBe(!hidden && now - last < POLL_IDLE_LIMIT_MS);
    }
  });
});

describe('createActivity', () => {
  it('stops polls after the idle limit and starts them again on input', () => {
    const t = setup();
    expect(t.activity.mayPoll()).toBe(true);
    t.advance(POLL_IDLE_LIMIT_MS);
    expect(t.activity.mayPoll()).toBe(false);
    const woke = vi.fn();
    t.activity.onWake(woke);
    t.doc.dispatchEvent(new Event('keydown'));
    expect(t.activity.mayPoll()).toBe(true);
    expect(woke).toHaveBeenCalledTimes(1);
    // An input while active does not wake again.
    t.doc.dispatchEvent(new Event('pointermove'));
    expect(woke).toHaveBeenCalledTimes(1);
  });

  it('stops polls while hidden and wakes them when visible', () => {
    const t = setup();
    const woke = vi.fn();
    t.activity.onWake(woke);
    t.doc.setVisible(false);
    expect(t.activity.mayPoll()).toBe(false);
    expect(woke).not.toHaveBeenCalled();
    t.advance(2 * POLL_IDLE_LIMIT_MS);
    t.doc.setVisible(true);
    expect(t.activity.mayPoll()).toBe(true);
    expect(woke).toHaveBeenCalledTimes(1);
  });

  it('removes all listeners on stop', () => {
    const t = setup();
    expect(t.doc.listeners).toBe(INPUT_EVENTS.length + 1);
    t.activity.stop();
    expect(t.doc.listeners).toBe(0);
  });
});

describe('poll', () => {
  it('runs at the interval, skips while idle, and runs one time at the wake', () => {
    vi.useFakeTimers();
    const t = setup();
    const fn = vi.fn();
    const stop = poll(fn, 1000, t.activity);
    vi.advanceTimersByTime(3000);
    expect(fn).toHaveBeenCalledTimes(3);
    t.advance(POLL_IDLE_LIMIT_MS);
    vi.advanceTimersByTime(10_000);
    expect(fn).toHaveBeenCalledTimes(3);
    t.doc.dispatchEvent(new Event('wheel'));
    expect(fn).toHaveBeenCalledTimes(4);
    vi.advanceTimersByTime(1000);
    expect(fn).toHaveBeenCalledTimes(5);
    stop();
  });

  it('does not run at a wake when no tick was skipped', () => {
    vi.useFakeTimers();
    const t = setup();
    const fn = vi.fn();
    const stop = poll(fn, 60_000, t.activity);
    t.doc.setVisible(false);
    t.doc.setVisible(true);
    expect(fn).not.toHaveBeenCalled();
    stop();
  });

  it('stop clears the timer and the wake listener', () => {
    vi.useFakeTimers();
    const t = setup();
    const fn = vi.fn();
    const stop = poll(fn, 1000, t.activity);
    t.advance(POLL_IDLE_LIMIT_MS);
    vi.advanceTimersByTime(1000);
    stop();
    expect(vi.getTimerCount()).toBe(0);
    t.doc.dispatchEvent(new Event('keydown'));
    vi.advanceTimersByTime(10_000);
    expect(fn).not.toHaveBeenCalled();
  });
});
