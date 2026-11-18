// Values of the packaged config (packaging/rusthole.toml), for tests.

import packagedToml from '../../../packaging/rusthole.toml?raw';

/** The `url` of each `[[upstreams.servers]]` table of the packaged config. */
export function packagedUpstreams(): string[] {
  const out: string[] = [];
  let inServer = false;
  for (const line of packagedToml.split(/\r?\n/)) {
    const t = line.trim();
    if (t.startsWith('[')) inServer = t === '[[upstreams.servers]]';
    const m = /^url\s*=\s*"([^"]*)"$/.exec(t);
    if (inServer && m?.[1]) out.push(m[1]);
  }
  return out;
}
