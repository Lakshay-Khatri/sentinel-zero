import type { Severity } from '../../types';

// Full class names are written out so Tailwind can find them when building.
const STYLES: Record<Severity, string> = {
  critical: 'bg-sev-critical-bg text-sev-critical-fg',
  high: 'bg-sev-high-bg text-sev-high-fg',
  medium: 'bg-sev-medium-bg text-sev-medium-fg',
  low: 'bg-sev-low-bg text-sev-low-fg',
  info: 'bg-sev-info-bg text-sev-info-fg',
};

export const SeverityBadge = ({ severity }: { severity: Severity }) => (
  <span className={`inline-block shrink-0 rounded px-2 py-0.5 text-[11px] font-bold uppercase tracking-wide ${STYLES[severity]}`}>
    {severity}
  </span>
);
