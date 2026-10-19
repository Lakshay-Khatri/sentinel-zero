import { useCallback, useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { Cookie, FileCode2, Loader2, Lock, Search, ShieldAlert, AlertCircle } from 'lucide-react';
import { Navbar } from '../components/Navbar';
import { Footer } from '../components/Footer';
import { Layout } from '../components/Layout';
import { ReportSummary } from '../components/report/ReportSummary';
import { FindingsSection } from '../components/report/FindingsSection';
import { TlsDetails } from '../components/report/TlsDetails';
import { performScan, healthCheck, ApiError } from '../services/api';
import { groupByCategory } from '../utils/findings';
import { normalizeTargetUrl } from '../utils/url';
import type { AnalysisReport } from '../types';

export const DashboardPage = () => {
  const [url, setUrl] = useState('');
  const [isOnline, setIsOnline] = useState<boolean>(false);
  const [isChecking, setIsChecking] = useState<boolean>(true);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [scanningUrl, setScanningUrl] = useState<string | null>(null);
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  // True only when the typed address itself failed the checks (not for backend errors).
  const [inputInvalid, setInputInvalid] = useState(false);

  // Re-checks the backend after a failed scan.
  const checkBackendHealth = useCallback(async () => {
    try {
      await healthCheck();
      setIsOnline(true);
    } catch {
      setIsOnline(false);
    } finally {
      setIsChecking(false);
    }
  }, []);

  // Initial status check when the page loads (isChecking starts as true).
  useEffect(() => {
    let cancelled = false;
    healthCheck()
      .then(() => { if (!cancelled) setIsOnline(true); })
      .catch(() => { if (!cancelled) setIsOnline(false); })
      .finally(() => { if (!cancelled) setIsChecking(false); });
    return () => { cancelled = true; };
  }, []);

  const handleScan = async (e: FormEvent) => {
    e.preventDefault();

    const checked = normalizeTargetUrl(url);
    setInputInvalid(!checked.ok);
    if (!checked.ok) {
      setError(checked.error);
      return;
    }

    setIsLoading(true);
    setScanningUrl(checked.url);
    setError(null);
    setReport(null);

    try {
      setReport(await performScan(checked.url));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'An unexpected error occurred.');
      // A failed request may mean the backend went down; refresh the status badge.
      setIsChecking(true);
      void checkBackendHealth();
    } finally {
      setIsLoading(false);
    }
  };

  const groups = report ? groupByCategory(report.findings) : null;
  const certFailed = report?.findings.some((f) => f.id === 'CERT_VERIFICATION_FAILED') ?? false;
  const skipped = certFailed
    ? 'Not checked: the certificate could not be verified, so no trusted connection was made.'
    : undefined;

  return (
    <Layout>
      <Navbar isOnline={isOnline} isChecking={isChecking} />

      <main className="mx-auto w-full max-w-5xl grow space-y-12 px-4 py-12 sm:px-6 sm:py-16">
        <section className="mx-auto max-w-3xl space-y-8 text-center">
          <div className="space-y-4">
            <h1 className="text-4xl font-bold leading-tight tracking-tight text-main-text md:text-6xl">
              Know your website’s <br className="hidden md:block" />
              <span className="text-primary-green">security posture.</span>
            </h1>
            <p className="mx-auto max-w-2xl text-base leading-relaxed text-secondary-text sm:text-lg">
              Sentinel Zero performs a passive security analysis of your HTTPS certificate,
              security headers and cookie attributes, using one ordinary request and without
              interacting destructively with your server.
            </p>
          </div>

          <form onSubmit={handleScan} noValidate className="mx-auto max-w-2xl text-left">
            <label htmlFor="target-url" className="sr-only">Website address to scan</label>
            <div className="flex flex-col gap-2 rounded-xl border border-subtle-border bg-surface p-2 shadow-sm transition-colors focus-within:border-primary-green sm:flex-row sm:items-center">
              <div className="flex min-w-0 grow items-center">
                <Search className="ml-3 h-5 w-5 shrink-0 text-secondary-text" aria-hidden="true" />
                <input
                  id="target-url"
                  type="text"
                  inputMode="url"
                  autoComplete="url"
                  spellCheck={false}
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://example.com"
                  aria-invalid={inputInvalid}
                  aria-describedby={error ? 'scan-error' : undefined}
                  className="w-full min-w-0 border-none bg-transparent px-3 py-3 text-lg text-main-text outline-none placeholder:text-secondary-text"
                  disabled={isLoading}
                />
              </div>
              <button
                type="submit"
                disabled={isLoading}
                className="flex items-center justify-center gap-2 rounded-lg bg-primary-green px-6 py-3 font-semibold text-white transition-colors hover:bg-deep-forest focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-deep-forest disabled:cursor-not-allowed disabled:opacity-60"
              >
                {isLoading && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
                {isLoading ? 'Analyzing…' : 'Analyze website'}
              </button>
            </div>
          </form>

          {error && (
            <div
              id="scan-error"
              role="alert"
              className="mx-auto flex max-w-xl items-start gap-3 rounded-lg border border-red-200 bg-red-50 p-4 text-left text-sm text-red-800"
            >
              <AlertCircle className="mt-0.5 h-5 w-5 shrink-0" aria-hidden="true" />
              <p>{error}</p>
            </div>
          )}
        </section>

        {isLoading && (
          <section
            role="status"
            className="flex flex-col items-center gap-3 rounded-2xl border border-subtle-border bg-surface p-10 text-center shadow-sm"
          >
            <Loader2 className="h-8 w-8 animate-spin text-primary-green" aria-hidden="true" />
            <p className="font-semibold text-main-text">Scanning {scanningUrl}…</p>
            <p className="text-sm text-secondary-text">
              Checking the certificate, security headers and cookies. This usually takes a few seconds.
            </p>
          </section>
        )}

        {report && groups && (
          <div className="space-y-8">
            <ReportSummary report={report} />

            <div className="space-y-6">
              <h2 className="text-xl font-bold text-main-text">Detailed findings</h2>
              <FindingsSection
                title="HTTPS & certificate"
                description="Encryption of the connection and the server's TLS certificate."
                icon={<Lock className="h-4 w-4" aria-hidden="true" />}
                findings={groups.tls}
                details={<TlsDetails report={report} />}
              />
              <FindingsSection
                title="Security headers"
                description="Browser protections the server enables through HTTP response headers."
                icon={<FileCode2 className="h-4 w-4" aria-hidden="true" />}
                findings={groups.headers}
                skippedReason={skipped}
              />
              <FindingsSection
                title="Cookies"
                description="Security attributes on cookies set by the response (values are never shown)."
                icon={<Cookie className="h-4 w-4" aria-hidden="true" />}
                findings={groups.cookies}
                skippedReason={skipped}
              />
            </div>
          </div>
        )}

        {!report && !isLoading && (
          <section className="space-y-4 rounded-3xl border-2 border-dashed border-subtle-border bg-surface p-10 text-center shadow-sm sm:p-16">
            <div className="mb-4 flex justify-center">
              <div className="rounded-full bg-slate-50 p-5">
                <ShieldAlert className="h-12 w-12 text-slate-400" aria-hidden="true" />
              </div>
            </div>
            <h2 className="text-2xl font-bold text-main-text">Ready for analysis</h2>
            <p className="mx-auto max-w-md leading-relaxed text-secondary-text">
              Enter a website address above to run a passive security scan.
            </p>
          </section>
        )}
      </main>

      <Footer />
    </Layout>
  );
};
