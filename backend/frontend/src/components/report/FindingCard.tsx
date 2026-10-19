import type { Finding } from '../../types';
import { SeverityBadge } from './SeverityBadge';

export const FindingCard = ({ finding }: { finding: Finding }) => (
  <article className="space-y-3 p-5 sm:p-6">
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
      <SeverityBadge severity={finding.severity} />
      <h4 className="text-base font-bold text-main-text sm:text-lg">{finding.title}</h4>
      <code className="text-[11px] text-secondary-text">{finding.id}</code>
    </div>

    <p className="max-w-3xl text-sm leading-relaxed text-secondary-text">{finding.explanation}</p>

    {finding.evidence && (
      <div className="rounded-lg border border-subtle-border bg-slate-50 p-3">
        <p className="mb-1 text-[11px] font-bold uppercase tracking-wide text-secondary-text">Evidence observed</p>
        <p className="whitespace-pre-wrap break-words font-mono text-xs text-main-text">{finding.evidence}</p>
      </div>
    )}

    <div className="rounded-lg bg-pale-sage/50 p-3">
      <p className="mb-1 text-[11px] font-bold uppercase tracking-wide text-deep-forest">How to fix</p>
      <p className="text-sm leading-relaxed text-main-text">{finding.remediation}</p>
    </div>
  </article>
);
