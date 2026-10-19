import { Info } from 'lucide-react';
import type { AnalysisReport } from '../../types';
import { SEVERITY_ORDER, countBySeverity } from '../../utils/findings';
import { SeverityBadge } from './SeverityBadge';

const Stat = ({ label, value, title }: { label: string; value: string; title?: string }) => (
  <div className="min-w-0 space-y-1 rounded-xl border border-subtle-border bg-surface p-5 shadow-sm">
    <p className="text-[11px] font-bold uppercase tracking-widest text-secondary-text">{label}</p>
    <p className="truncate font-medium text-main-text" title={title ?? value}>{value}</p>
  </div>
);

export const ReportSummary = ({ report }: { report: AnalysisReport }) => {
  const counts = countBySeverity(report.findings);
  const total = report.findings.length;

  return (
    <section aria-labelledby="summary-heading" className="space-y-4">
      <h2 id="summary-heading" className="text-xl font-bold text-main-text">Scan summary</h2>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Stat label="Target URL" value={report.target_url} />
        <Stat label="Connected IP" value={report.validated_ip} title="The public IP address the scanner connected to" />
        <Stat label="Total findings" value={String(total)} />
      </div>

      <div className="rounded-xl border border-subtle-border bg-surface p-4 shadow-sm">
        <p className="mb-3 text-[11px] font-bold uppercase tracking-widest text-secondary-text">Findings by severity</p>
        <ul className="flex flex-wrap gap-2">
          {SEVERITY_ORDER.map((severity) => (
            <li
              key={severity}
              className={`flex items-center gap-2 rounded-lg border border-subtle-border px-3 py-1.5 ${counts[severity] === 0 ? 'opacity-60' : ''}`}
            >
              <SeverityBadge severity={severity} />
              <span className="text-sm font-semibold text-main-text">{counts[severity]}</span>
            </li>
          ))}
        </ul>
        {total === 0 && (
          <p className="mt-3 text-sm text-secondary-text">
            No issues were detected by this passive scan. This does not mean the website is fully
            secure: only HTTPS, security headers and cookies from a single request were checked.
          </p>
        )}
      </div>

      {report.scan_metadata.note && (
        <p className="flex items-start gap-2 rounded-lg border border-sev-medium-bg bg-sev-medium-bg/50 p-3 text-sm text-sev-medium-fg" role="note">
          <Info className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
          {report.scan_metadata.note}
        </p>
      )}
    </section>
  );
};
