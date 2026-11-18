// @vitest-environment happy-dom
import { flushSync, mount, unmount } from 'svelte';
import { afterEach, describe, expect, it } from 'vitest';
import type { SystemInfo } from '../lib/api/types';
import SystemInfoList from './SystemInfoList.svelte';

const BASE: SystemInfo = {
  version: '0.1.0',
  commit: null,
  started_at: '2026-11-17T08:00:00Z',
  uptime_seconds: 3600,
  memory_rss_bytes: 1024,
  list_entries: 10,
  config_path: '/etc/rusthole/rusthole.toml',
  data_dir: '/var/lib/rusthole',
  os: 'linux',
  arch: 'x86_64',
  listeners: [],
};

let cleanup: (() => void) | null = null;
afterEach(() => {
  cleanup?.();
  cleanup = null;
  document.body.innerHTML = '';
});

function render(info: SystemInfo): HTMLElement {
  const target = document.createElement('div');
  document.body.append(target);
  const c = mount(SystemInfoList, { target, props: { info } });
  cleanup = () => void unmount(c);
  flushSync();
  return target;
}

describe('SystemInfoList', () => {
  it('shows two listeners of the same kind (M4)', () => {
    // GET /system with the packaged config ("auto") on a host with a LAN address.
    const target = render({
      ...BASE,
      listeners: [
        { kind: 'dns', address: '127.0.0.1:53' },
        { kind: 'dns', address: '192.0.2.2:53' },
        { kind: 'admin', address: '127.0.0.1:8443' },
        { kind: 'admin', address: '192.0.2.2:8443' },
      ],
    });
    const rows = [...target.querySelectorAll('.listener')].map((r) => r.textContent?.replace(/\s+/g, ' ').trim());
    expect(rows).toEqual(['dns 127.0.0.1:53', 'dns 192.0.2.2:53', 'admin 127.0.0.1:8443', 'admin 192.0.2.2:8443']);
  });
});
