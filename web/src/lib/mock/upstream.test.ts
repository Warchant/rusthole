import { describe, expect, it } from 'vitest';
import { packagedUpstreams } from '../../test/packaged';
import { parseUpstreamUrl, upstreamErrors } from './upstream';

// The vectors of `upstream_forms` in crates/rusthole-core/src/net.rs.
describe('parseUpstreamUrl (the mock port of UpstreamUrl::parse)', () => {
  it.each([
    ['8.8.8.8', 'udp', 53, ''],
    ['udp://192.0.2.1:5353', 'udp', 5353, ''],
    ['tcp://[2001:db8::1]', 'tcp', 53, ''],
    ['tls://dns.example', 'tls', 853, ''],
    ['https://dns.example/dns-query', 'https', 443, '/dns-query'],
    ['https://dns.example:8443', 'https', 8443, '/dns-query'],
    ['192.0.2.1:53', 'udp', 53, ''],
    [' UDP://192.0.2.1 ', 'udp', 53, ''],
    ['tls://192.0.2.1/', 'tls', 853, ''],
  ])('accepts %j', (input, transport, port, path) => {
    expect(parseUpstreamUrl(input)).toMatchObject({ ok: true, value: { transport, port, path } });
  });

  it.each([
    ['ftp://192.0.2.1', /no scheme/],
    ['udp://dns.example', /must be an IP address/],
    ['udp://192.0.2.1:0', /port 0/],
    ['tls://dns.example/path', /not a valid upstream URL/],
    ['https://user@dns.example/', /not a valid upstream URL/],
    ['https://', /not a valid upstream URL/],
    ['dns.example', /not an address/],
    ['192.0.2.1:99999', /not an address/],
  ])('refuses %j', (input, message) => {
    const r = parseUpstreamUrl(input);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(message);
  });

  it('accepts the upstreams of the packaged config', () => {
    const packaged = packagedUpstreams();
    expect(packaged.length).toBeGreaterThan(0);
    for (const s of packaged) expect(parseUpstreamUrl(s).ok, s).toBe(true);
    expect(upstreamErrors(packaged, 2000, [])).toEqual([]);
  });

  it('gives the field errors of the server', () => {
    expect(upstreamErrors([], 50, [])).toEqual([
      { field: 'upstreams.servers', message: 'Give 1 to 8 servers.' },
      { field: 'upstreams.timeout_ms', message: 'Use 100 to 10000.' },
    ]);
    expect(upstreamErrors(['tls://dns.example'], 2000, ['tls://dns.example'])).toEqual([]);
    expect(upstreamErrors(['tls://dns.example'], 2000, [])[0]?.field).toBe('upstreams.servers[0]');
    expect(upstreamErrors(['udp://[2001:db8::1]:53'], 2000, [])[0]?.message).toMatch(/IPv6/);
    // The bootstrap check runs only when each field is good.
    expect(upstreamErrors(['tls://new.example', 'udp://dns.example'], 2000, []).map((e) => e.field)).toEqual(['upstreams.servers[1]']);
  });
});
