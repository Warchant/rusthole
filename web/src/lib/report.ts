// The sections of the domain report (docs/API.md section 17), in the order of the UI.

import type { ReportSection, ReportStatus } from './api/types';

export const REPORT_SECTIONS: { id: ReportSection; title: string }[] = [{ id: 'dns', title: 'DNS records' }];

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
