import { describe, expect, it } from 'vitest';
import {
  checkCidrs,
  checkServers,
  classifyClientMatch,
  IPV6_HINT,
  isHttpUrl,
  isIPv4,
  isIPv4Cidr,
  isIPv4WithPort,
  isMac,
  looksLikeIPv6,
  splitList,
} from './validate';

describe('IPv4 checks', () => {
  it.each(['192.0.2.1', '0.0.0.0', '255.255.255.255', '10.0.0.10'])('accepts %s', (s) => {
    expect(isIPv4(s)).toBe(true);
  });
  it.each(['256.0.0.1', '1.2.3', '1.2.3.4.5', '01.2.3.4', 'a.b.c.d', '', '1.2.3.4 '])('rejects %j', (s) => {
    expect(isIPv4(s)).toBe(false);
  });
  it('checks CIDRs', () => {
    expect(isIPv4Cidr('198.51.100.0/24')).toBe(true);
    expect(isIPv4Cidr('0.0.0.0/0')).toBe(true);
    expect(isIPv4Cidr('192.0.2.0/33')).toBe(false);
    expect(isIPv4Cidr('192.0.2.0/24/1')).toBe(false);
    expect(isIPv4Cidr('192.0.2.0')).toBe(false);
  });
  it('checks an address with a port', () => {
    expect(isIPv4WithPort('192.0.2.1:53')).toBe(true);
    expect(isIPv4WithPort('192.0.2.1')).toBe(true);
    expect(isIPv4WithPort('192.0.2.1:0')).toBe(false);
    expect(isIPv4WithPort('192.0.2.1:70000')).toBe(false);
  });
});

describe('MAC and IPv6 checks', () => {
  it('checks MAC addresses', () => {
    expect(isMac('02:00:00:00:00:01')).toBe(true);
    expect(isMac('02-00-00-00-00-0A')).toBe(true);
    expect(isMac('02:00-00:00:00:01')).toBe(false);
    expect(isMac('02:00:00:00:00')).toBe(false);
  });
  it('finds IPv6 values, but not MAC addresses', () => {
    expect(looksLikeIPv6('2001:db8::1')).toBe(true);
    expect(looksLikeIPv6('2001:db8::/64')).toBe(true);
    expect(looksLikeIPv6('::1')).toBe(true);
    expect(looksLikeIPv6('[2001:db8::1]:53')).toBe(true);
    expect(looksLikeIPv6('02:00:00:00:00:01')).toBe(false);
    expect(looksLikeIPv6('192.0.2.1:53')).toBe(false);
  });
});

describe('classifyClientMatch', () => {
  it.each([
    ['192.0.2.10', 'ip'],
    ['192.0.2.0/24', 'cidr'],
    ['02:00:00:00:00:01', 'mac'],
    ['laptop.lan', 'host'],
    ['tv', 'host'],
  ])('%s is %s', (s, kind) => {
    expect(classifyClientMatch(s)).toEqual({ ok: true, value: kind });
  });
  it('rejects IPv6 with the hint (A11)', () => {
    expect(classifyClientMatch('2001:db8::10')).toEqual({ ok: false, error: IPV6_HINT });
  });
  it.each(['', '999.0.0.1', '192.0.2.0/40', 'bad host!'])('rejects %j', (s) => {
    expect(classifyClientMatch(s).ok).toBe(false);
  });
});

describe('lists of servers and CIDRs', () => {
  it('checks servers', () => {
    expect(checkServers(['192.0.2.53', '198.51.100.53:5353'], 8)).toBeNull();
    expect(checkServers([], 8)).toMatch(/at least one/);
    expect(checkServers(['2001:db8::53'], 8)).toContain(IPV6_HINT);
    expect(checkServers(['dns.example'], 8)).toMatch(/IPv4/);
    expect(checkServers(['192.0.2.1', '192.0.2.2'], 1)).toMatch(/at most 1/);
  });
  it('checks CIDRs', () => {
    expect(checkCidrs([], 64)).toBeNull();
    expect(checkCidrs(['198.51.100.0/24'], 64)).toBeNull();
    expect(checkCidrs(['2001:db8::/64'], 64)).toContain(IPV6_HINT);
    expect(checkCidrs(['198.51.100.0'], 64)).toMatch(/IPv4 CIDR/);
  });
  it('splits text on commas, spaces and lines', () => {
    expect(splitList(' 192.0.2.1, 192.0.2.2\n192.0.2.3  ')).toEqual(['192.0.2.1', '192.0.2.2', '192.0.2.3']);
    expect(splitList('')).toEqual([]);
  });
  it('accepts only http and https URLs', () => {
    expect(isHttpUrl('https://lists.example.org/hosts.txt')).toBe(true);
    expect(isHttpUrl('ftp://lists.example.org/hosts.txt')).toBe(false);
    expect(isHttpUrl('not a url')).toBe(false);
  });
});
