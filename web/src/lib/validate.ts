// Form checks in the browser. The server checks again; these checks only give
// fast feedback. rusthole v1 uses IPv4 transport only (PLAN.md, A11).

import type { ClientKind } from './api/types';

export const IPV6_HINT = 'IPv6 comes in a later version. Use an IPv4 address.';

export function isIPv4(s: string): boolean {
  const parts = s.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => /^(0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255);
}

export function isIPv4Cidr(s: string): boolean {
  const [ip, prefix, extra] = s.split('/');
  if (extra !== undefined || ip === undefined || prefix === undefined) return false;
  if (!/^(0|[1-9]\d?)$/.test(prefix) || Number(prefix) > 32) return false;
  return isIPv4(ip);
}

/** IPv4 with an optional port: "192.0.2.1" or "192.0.2.1:53". */
export function isIPv4WithPort(s: string): boolean {
  const [ip, port, extra] = s.split(':');
  if (extra !== undefined || ip === undefined) return false;
  if (port === undefined) return isIPv4(ip);
  return isIPv4(ip) && /^[1-9]\d{0,4}$/.test(port) && Number(port) <= 65535;
}

export function isMac(s: string): boolean {
  return /^[0-9a-f]{2}([:-])[0-9a-f]{2}(\1[0-9a-f]{2}){4}$/i.test(s);
}

/** True when the text looks like an IPv6 address or prefix (two or more ':' and hex). */
export function looksLikeIPv6(s: string): boolean {
  const t = s.trim().replace(/^\[|\](:\d+)?$/g, '');
  if (isMac(t)) return false;
  return /^[0-9a-f:.]*:[0-9a-f:.]*:[0-9a-f:.]*(\/\d{1,3})?$/i.test(t);
}

export function isHostname(s: string): boolean {
  if (s.length === 0 || s.length > 253) return false;
  const name = s.endsWith('.') ? s.slice(0, -1) : s;
  return name
    .split('.')
    .every((label) => /^[a-z0-9_]([a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
}

export type Check<T> = { ok: true; value: T } | { ok: false; error: string };

/** Finds the kind of a configured client id (docs/API.md, section 9). */
export function classifyClientMatch(input: string): Check<ClientKind> {
  const s = input.trim();
  if (s === '') return { ok: false, error: 'Enter an IP address, CIDR, MAC address or host name.' };
  if (looksLikeIPv6(s)) return { ok: false, error: IPV6_HINT };
  if (isIPv4(s)) return { ok: true, value: 'ip' };
  if (s.includes('/')) {
    return isIPv4Cidr(s) ? { ok: true, value: 'cidr' } : { ok: false, error: 'This CIDR is not valid.' };
  }
  if (isMac(s)) return { ok: true, value: 'mac' };
  if (/^[\d.]+$/.test(s)) return { ok: false, error: 'This IPv4 address is not valid.' };
  if (isHostname(s)) return { ok: true, value: 'host' };
  return { ok: false, error: 'Enter an IP address, CIDR, MAC address or host name.' };
}

/** Checks a list of IPv4 servers (upstreams, conditional forwarding). */
export function checkServers(list: string[], max: number): string | null {
  if (list.length === 0) return 'Enter at least one server.';
  if (list.length > max) return `Enter at most ${max} servers.`;
  for (const s of list) {
    if (looksLikeIPv6(s)) return `${s}: ${IPV6_HINT}`;
    if (!isIPv4WithPort(s)) return `${s}: use an IPv4 address with an optional port.`;
  }
  return null;
}

export function checkCidrs(list: string[], max: number): string | null {
  if (list.length > max) return `Enter at most ${max} CIDRs.`;
  for (const s of list) {
    if (looksLikeIPv6(s)) return `${s}: ${IPV6_HINT}`;
    if (!isIPv4Cidr(s)) return `${s}: use an IPv4 CIDR, for example 198.51.100.0/24.`;
  }
  return null;
}

/** Splits a text box value on commas, spaces and new lines. */
export function splitList(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter((s) => s !== '');
}

export function isHttpUrl(s: string): boolean {
  try {
    const u = new URL(s);
    return (u.protocol === 'http:' || u.protocol === 'https:') && u.hostname !== '';
  } catch {
    return false;
  }
}
