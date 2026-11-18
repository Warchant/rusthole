// @vitest-environment happy-dom
// m17: background polls must not keep a session alive forever. They stop while the
// tab is hidden and after a long time with no user input.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { POLL_IDLE_LIMIT_MS, resetPageActivity } from '../lib/activity';
import Queries from '../pages/Queries.svelte';
import { cleanup, json, render, startMockApi } from '../test/harness';
import BlockingControl from './BlockingControl.svelte';

const MINUTE = 60_000;

function setHidden(hidden: boolean) {
  Object.defineProperty(document, 'visibilityState', { value: hidden ? 'hidden' : 'visible', configurable: true });
  document.dispatchEvent(new Event('visibilitychange'));
}

beforeEach(() => {
  setHidden(false);
  resetPageActivity();
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  setHidden(false);
  resetPageActivity();
});

async function startWithFakeTimers() {
  // Small answers for recent queries, so that many polls run fast.
  const t = await startMockApi((url) => (url.includes('/queries/recent') ? json(200, { items: [], next_cursor: null }) : null));
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'performance', 'Date'] });
  // A user input now: the idle time starts here.
  document.dispatchEvent(new KeyboardEvent('keydown'));
  return t;
}

const count = (calls: string[], path: string) => calls.filter((c) => c.startsWith(path)).length;

describe.each([
  ['BlockingControl', BlockingControl, 'GET /blocking'],
  ['Queries', Queries, 'GET /queries/recent'],
] as const)('%s polls', (_name, component, path) => {
  it('stop after a long time with no user input, and start again on input', async () => {
    const t = await startWithFakeTimers();
    render(component);
    await vi.advanceTimersByTimeAsync(5 * MINUTE);
    expect(count(t.calls, path)).toBeGreaterThan(1);

    await vi.advanceTimersByTimeAsync(POLL_IDLE_LIMIT_MS);
    const atIdle = count(t.calls, path);
    await vi.advanceTimersByTimeAsync(60 * MINUTE);
    expect(count(t.calls, path)).toBe(atIdle);

    // The user comes back: one poll at once, then the normal interval.
    document.dispatchEvent(new PointerEvent('pointerdown'));
    await vi.advanceTimersByTimeAsync(10);
    expect(count(t.calls, path)).toBe(atIdle + 1);
    await vi.advanceTimersByTimeAsync(2 * MINUTE);
    expect(count(t.calls, path)).toBeGreaterThan(atIdle + 1);
  });

  it('stop while the tab is hidden, and start again when it is visible', async () => {
    const t = await startWithFakeTimers();
    render(component);
    await vi.advanceTimersByTimeAsync(MINUTE);
    setHidden(true);
    await vi.advanceTimersByTimeAsync(10);
    const atHide = count(t.calls, path);
    await vi.advanceTimersByTimeAsync(10 * MINUTE);
    expect(count(t.calls, path)).toBe(atHide);
    setHidden(false);
    await vi.advanceTimersByTimeAsync(10);
    expect(count(t.calls, path), t.calls.slice(-6).join(', ')).toBe(atHide + 1);
  });
});
