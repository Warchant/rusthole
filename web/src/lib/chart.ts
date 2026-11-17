// Pure helpers for the SVG charts.

/** A "nice" step (1, 2 or 5 times a power of 10) that gives about `count` ticks up to `max`. */
export function niceStep(max: number, count: number): number {
  if (max <= 0 || count <= 0) return 1;
  const raw = max / count;
  const power = 10 ** Math.floor(Math.log10(raw));
  const f = raw / power;
  const nice = f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10;
  return Math.max(1, nice * power);
}

/** Tick values from 0 to at least `max`. The last tick is the top of the axis. */
export function niceTicks(max: number, count = 4): number[] {
  const step = niceStep(max, count);
  const top = Math.max(step, Math.ceil(max / step) * step);
  const ticks: number[] = [];
  for (let v = 0; v <= top + step / 2; v += step) ticks.push(v);
  return ticks;
}

/** SVG path for a filled area. `ys` are already in pixels. */
export function areaPath(xs: number[], ys: number[], baseline: number): string {
  if (xs.length === 0) return '';
  let d = `M${xs[0]},${baseline}`;
  for (let i = 0; i < xs.length; i++) d += `L${xs[i]},${ys[i]}`;
  d += `L${xs[xs.length - 1]},${baseline}Z`;
  return d;
}

/** SVG path for a line. */
export function linePath(xs: number[], ys: number[]): string {
  return xs.map((x, i) => `${i === 0 ? 'M' : 'L'}${x},${ys[i]}`).join('');
}

/** The index of the bucket under pixel `x` for `n` buckets on `width` pixels. */
export function bucketAt(x: number, width: number, n: number): number {
  if (n <= 0 || width <= 0) return -1;
  const i = Math.floor((x / width) * n);
  return Math.min(n - 1, Math.max(0, i));
}
