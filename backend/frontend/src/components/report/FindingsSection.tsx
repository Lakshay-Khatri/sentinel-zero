import type { ReactNode } from 'react';
import { CheckCircle2, MinusCircle } from 'lucide-react';
import type { Finding } from '../../types';
import { FindingCard } from './FindingCard';

interface Props {
  title: string;
  description: string;
  icon: ReactNode;
  findings: Finding[];
  /** When set, this area was not checked; the text explains why. */
  skippedReason?: string;
  /** Optional observed details shown above the findings (e.g. TLS connection info). */
  details?: ReactNode;
}

export const FindingsSection = ({ title, description, icon, findings, skippedReason, details }: Props) => (
  <section className="overflow-hidden rounded-2xl border border-subtle-border bg-surface shadow-sm">
    <header className="flex items-start justify-between gap-4 border-b border-subtle-border bg-slate-50/60 px-5 py-4 sm:px-6">
      <div className="flex items-start gap-3">
        <div className="mt-0.5 rounded-md bg-pale-sage p-1.5 text-deep-forest">{icon}</div>
        <div>
          <h3 className="text-base font-bold text-main-text sm:text-lg">{title}</h3>
          <p className="text-xs text-secondary-text sm:text-sm">{description}</p>
        </div>
      </div>
      {!skippedReason && (
        <span className="shrink-0 rounded-full border border-subtle-border bg-surface px-2.5 py-0.5 text-xs font-semibold text-main-text">
          {findings.length} {findings.length === 1 ? 'finding' : 'findings'}
        </span>
      )}
    </header>

    {details}

    {skippedReason ? (
      <p className="flex items-center gap-2 px-5 py-5 text-sm text-secondary-text sm:px-6">
        <MinusCircle className="h-4 w-4 shrink-0" aria-hidden="true" /> {skippedReason}
      </p>
    ) : findings.length === 0 ? (
      <p className="flex items-center gap-2 px-5 py-5 text-sm text-primary-green sm:px-6">
        <CheckCircle2 className="h-4 w-4 shrink-0" aria-hidden="true" />
        No issues detected by this passive check.
      </p>
    ) : (
      <div className="divide-y divide-subtle-border">
        {findings.map((finding, idx) => (
          // Cookie findings can share an ID (one per cookie), so the index keeps keys unique.
          <FindingCard key={`${finding.id}-${idx}`} finding={finding} />
        ))}
      </div>
    )}
  </section>
);
