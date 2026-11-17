import { describe, expect, it } from 'vitest';
import {
  formatBytes,
  formatCount,
  formatCountdown,
  formatDuration,
  formatHour,
  formatPercent,
  formatRelative,
  parseDurationInput,
} from './format';
import { MAX_TIMER_SECONDS, remainingSeconds, TIMER_PRESETS } from './countdown';

describe('timer formatting', () => {
  it.each([
    [0, '0:00'],
    [5, '0:05'],
    [59, '0:59'],
    [60, '1:00'],
    [287, '4:47'],
    [3599, '59:59'],
    [3600, '1:00:00'],
    [3725, '1:02:05'],
    [86400, '24:00:00'],
  ])('formatCountdown(%i) = %s', (s, text) => {
    expect(formatCountdown(s)).toBe(text);
  });

  it('formatCountdown clamps negative and fractional values', () => {
    expect(formatCountdown(-3)).toBe('0:00');
    expect(formatCountdown(59.9)).toBe('0:59');
  });

  it.each([
    [30, '30 s'],
    [300, '5 min'],
    [330, '5 min 30 s'],
    [3600, '1 h'],
    [5400, '1 h 30 min'],
    [86400, '1 d'],
    [93600, '1 d 2 h'],
  ])('formatDuration(%i) = %s', (s, text) => {
    expect(formatDuration(s)).toBe(text);
  });

  it('the presets give the labels that they show', () => {
    for (const p of TIMER_PRESETS) expect(formatDuration(p.seconds)).toBe(p.label);
  });
});

describe('parseDurationInput', () => {
  it.each([
    ['90', 90],
    ['90s', 90],
    ['5m', 300],
    ['1h', 3600],
    ['1h30m', 5400],
    ['1h 30m 15s', 5415],
    [' 2M ', 120],
  ])('parses %j as %i seconds', (text, s) => {
    expect(parseDurationInput(text)).toBe(s);
  });

  it.each(['', '0', 'abc', '5x', '1h-', 'm5', '0m'])('rejects %j', (text) => {
    expect(parseDurationInput(text)).toBeNull();
  });
});

describe('remainingSeconds', () => {
  it('counts down with the monotonic clock', () => {
    expect(remainingSeconds(300, 1000, 1000)).toBe(300);
    expect(remainingSeconds(300, 1000, 1500)).toBe(300);
    expect(remainingSeconds(300, 1000, 2000)).toBe(299);
    expect(remainingSeconds(300, 1000, 1000 + 300_000)).toBe(0);
  });
  it('never goes below 0 and ignores a clock that goes back', () => {
    expect(remainingSeconds(10, 0, 999_999)).toBe(0);
    expect(remainingSeconds(10, 5000, 1000)).toBe(10);
  });
  it('the maximum timer is one day', () => {
    expect(MAX_TIMER_SECONDS).toBe(86400);
  });
});

describe('number formatting', () => {
  it('formats counts and percents', () => {
    expect(formatCount(48210)).toBe('48,210');
    expect(formatPercent(12.694)).toBe('12.7%');
    expect(formatPercent(Number.NaN)).toBe('0%');
  });
  it('formats bytes', () => {
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(41943040)).toBe('40.0 MiB');
    expect(formatBytes(null)).toBe('unknown');
  });
  it('formats hours', () => {
    expect(formatHour(7)).toBe('07:00');
    expect(formatHour(23)).toBe('23:00');
  });
});

describe('formatRelative', () => {
  const now = Date.parse('2026-11-17T08:00:00Z');
  it.each([
    ['2026-11-17T07:59:50Z', 'just now'],
    ['2026-11-17T07:55:00Z', '5 min ago'],
    ['2026-11-17T05:00:00Z', '3 h ago'],
    ['2026-11-15T08:00:00Z', '2 d ago'],
    ['2026-11-17T08:05:00Z', 'in 5 min'],
  ])('%s -> %s', (iso, text) => {
    expect(formatRelative(iso, now)).toBe(text);
  });
  it('handles null and bad values', () => {
    expect(formatRelative(null, now)).toBe('never');
    expect(formatRelative('bad', now)).toBe('unknown');
  });
});
