// Pure format helpers. They use the "en-US" locale, so the output is the same
// on each machine and in tests.

const intFmt = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 });
const compactFmt = new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 });

export function formatCount(n: number): string {
  return intFmt.format(n);
}

/** 1234 -> "1.2K". Use it on axis labels. */
export function formatCompact(n: number): string {
  return compactFmt.format(n);
}

/** 12.694 -> "12.7%". */
export function formatPercent(p: number, digits = 1): string {
  if (!Number.isFinite(p)) return '0%';
  return `${p.toFixed(digits)}%`;
}

/** Countdown text: 287 -> "4:47", 3725 -> "1:02:05". */
export function formatCountdown(totalSeconds: number): string {
  const s = Math.max(0, Math.floor(totalSeconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const ss = String(sec).padStart(2, '0');
  if (h > 0) return `${h}:${String(m).padStart(2, '0')}:${ss}`;
  return `${m}:${ss}`;
}

/** Short duration text: 30 -> "30 s", 300 -> "5 min", 3600 -> "1 h", 93600 -> "1 d 2 h". */
export function formatDuration(totalSeconds: number): string {
  const s = Math.max(0, Math.floor(totalSeconds));
  if (s < 60) return `${s} s`;
  if (s < 3600) {
    const m = Math.floor(s / 60);
    const rest = s % 60;
    return rest ? `${m} min ${rest} s` : `${m} min`;
  }
  if (s < 86400) {
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    return m ? `${h} h ${m} min` : `${h} h`;
  }
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  return h ? `${d} d ${h} h` : `${d} d`;
}

/**
 * Reads a timer value that a person types: "90", "90s", "5m", "1h", "1h30m".
 * A bare number is seconds. Returns seconds, or null for a bad value.
 */
export function parseDurationInput(text: string): number | null {
  const t = text.trim().toLowerCase().replace(/\s+/g, '');
  if (t === '') return null;
  if (/^\d+$/.test(t)) {
    const n = Number.parseInt(t, 10);
    return n > 0 ? n : null;
  }
  const re = /(\d+)(h|m|s)/gy;
  let total = 0;
  let consumed = 0;
  let match: RegExpExecArray | null;
  while ((match = re.exec(t)) !== null) {
    const n = Number.parseInt(match[1] ?? '0', 10);
    const unit = match[2];
    total += unit === 'h' ? n * 3600 : unit === 'm' ? n * 60 : n;
    consumed = re.lastIndex;
  }
  if (consumed !== t.length || total <= 0) return null;
  return total;
}

export function formatBytes(n: number | null): string {
  if (n === null) return 'unknown';
  const units = ['B', 'KiB', 'MiB', 'GiB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${i === 0 ? v : v.toFixed(1)} ${units[i]}`;
}

/** "5 min ago" text for a time stamp. `nowMs` is an input, for tests. */
export function formatRelative(iso: string | null, nowMs: number): string {
  if (!iso) return 'never';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return 'unknown';
  const diff = Math.round((nowMs - t) / 1000);
  if (diff < 0) return `in ${formatDuration(-diff)}`;
  if (diff < 45) return 'just now';
  if (diff < 3600) return `${Math.round(diff / 60)} min ago`;
  if (diff < 86400) return `${Math.round(diff / 3600)} h ago`;
  return `${Math.round(diff / 86400)} d ago`;
}

const dateTimeFmt = new Intl.DateTimeFormat(undefined, {
  year: 'numeric',
  month: 'short',
  day: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
});

/** Local date and time for people. */
export function formatDateTime(iso: string | null): string {
  if (!iso) return 'never';
  const t = Date.parse(iso);
  return Number.isNaN(t) ? 'unknown' : dateTimeFmt.format(t);
}

/** 7 -> "07:00". */
export function formatHour(hour: number): string {
  return `${String(hour).padStart(2, '0')}:00`;
}
