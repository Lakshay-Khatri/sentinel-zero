import type { AnalysisReport } from '../../types';

/** Shows only what the backend observed on its TLS connection; nothing is inferred. */
export const TlsDetails = ({ report }: { report: AnalysisReport }) => {
  const meta = report.scan_metadata;
  const isHttp = report.target_url.toLowerCase().startsWith('http://');
  const certFailed = report.findings.some((f) => f.id === 'CERT_VERIFICATION_FAILED');

  if (!meta.tls_version) {
    const message = isHttp
      ? 'This scan used plain HTTP, so there was no encrypted connection to describe.'
      : certFailed
        ? 'The certificate could not be verified, so no connection details were collected. See the finding below.'
        : 'Connection details were not available for this scan.';
    return <p className="px-5 pt-4 text-sm text-secondary-text sm:px-6">{message}</p>;
  }

  const rows: [string, string | undefined][] = [
    ['Protocol', meta.tls_version],
    ['Cipher', meta.tls_cipher],
    ['Issued to', meta.cert_subject],
    ['Issued by', meta.cert_issuer],
    ['Valid until', meta.cert_valid_until],
    ['Days remaining', meta.cert_days_remaining],
  ];

  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-2 px-5 pt-4 text-sm sm:grid-cols-2 sm:px-6">
      {rows
        .filter(([, value]) => value)
        .map(([label, value]) => (
          <div key={label} className="flex min-w-0 justify-between gap-3 border-b border-subtle-border/60 py-1.5">
            <dt className="shrink-0 text-secondary-text">{label}</dt>
            <dd className="truncate text-right font-medium text-main-text" title={value}>{value}</dd>
          </div>
        ))}
    </dl>
  );
};
