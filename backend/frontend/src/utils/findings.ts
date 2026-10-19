import type { Finding, Severity } from '../types';

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export type Category = 'tls' | 'headers' | 'cookies';

export const CATEGORY_ORDER: Category[] = ['tls', 'headers', 'cookies'];

/** Which part of the report a finding belongs to, based on its stable ID (see docs/SEVERITY.md). */
export const categoryOf = (id: string): Category => {
  if (id.startsWith('COOKIE_')) return 'cookies';
  if (id === 'NO_HTTPS' || id === 'HTTP_REDIRECTS_TO_HTTPS' || id.startsWith('CERT_') || id.startsWith('TLS_')) {
    return 'tls';
  }
  return 'headers';
};

/** Most severe first; findings with equal severity keep the backend's order. */
export const sortBySeverity = (findings: Finding[]): Finding[] =>
  [...findings].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));

export const countBySeverity = (findings: Finding[]): Record<Severity, number> => {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
};

export const groupByCategory = (findings: Finding[]): Record<Category, Finding[]> => {
  const groups: Record<Category, Finding[]> = { tls: [], headers: [], cookies: [] };
  for (const finding of findings) groups[categoryOf(finding.id)].push(finding);
  for (const category of CATEGORY_ORDER) groups[category] = sortBySeverity(groups[category]);
  return groups;
};
