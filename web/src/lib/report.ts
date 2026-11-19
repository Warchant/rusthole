// The sections of the domain report (docs/API.md section 17), in the order of the UI.

import type { ReportSection, ReportStatus } from './api/types';

export const REPORT_SECTIONS: { id: ReportSection; title: string }[] = [
  { id: 'dns', title: 'DNS records' },
  { id: 'rdap', title: 'Registration (RDAP)' },
  { id: 'tls', title: 'TLS certificate (port 443)' },
  { id: 'reputation', title: 'Reputation signals' },
];

/** Text for the verdict of a filtering resolver. */
export function verdictText(v: string | null): string {
  switch (v) {
    case 'blocked':
      return 'blocks it (malware or phishing list)';
    case 'allowed':
      return 'does not block it';
    case 'no_such_name':
      return 'the name does not exist';
    case 'unknown':
      return 'no clear result';
    default:
      return 'no answer';
  }
}

/** The age of a date in whole days at `nowMs`, or null. */
export function ageDays(iso: string | null, nowMs: number): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.floor((nowMs - t) / 86_400_000);
}

/** Text for a section state. */
export function statusText(s: ReportStatus): string {
  switch (s) {
    case 'ok':
      return 'ok';
    case 'failed':
      return 'failed';
    case 'off':
      return 'turned off';
    case 'unavailable':
      return 'not available';
  }
}
