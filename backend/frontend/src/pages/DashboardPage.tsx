import { useState, useEffect } from 'react';
import { Navbar } from '../components/Navbar';
import { Footer } from '../components/Footer';
import { Layout } from '../components/Layout';
import { Search, ShieldAlert, Loader2, AlertCircle, CheckCircle2 } from 'lucide-react';
import { performScan, healthCheck, ApiError } from '../services/api';
import type { AnalysisReport } from '../types';

export const DashboardPage = () => {
  const [url, setUrl] = useState('');
  const [isOnline, setIsOnline] = useState<boolean>(false);
  const [isChecking, setIsChecking] = useState<boolean>(true);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    checkBackendHealth();
  }, []);

  const checkBackendHealth = async () => {
    setIsChecking(true);
    try {
      await healthCheck();
      setIsOnline(true);
    } catch (e) {
      setIsOnline(false);
    } finally {
      setIsChecking(false);
    }
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) return;

    setIsLoading(true);
    setError(null);
    setReport(null);

    try {
      const data = await performScan(url);
      setReport(data);
    } catch (e: any) {
      if (e instanceof ApiError) {
        setError(e.detail || 'An internal server error occurred.');
      } else {
        setError('Network error: Could not connect to the security backend.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Layout>
      <Navbar isOnline={isOnline} isChecking={isChecking} />

      <main className="flex-grow max-w-5xl mx-auto w-full px-6 py-20 space-y-20">
        <section className="text-center space-y-8 max-w-3xl mx-auto">
          <div className="space-y-4">
            <h1 className="text-4xl md:text-6xl font-bold text-main-text tracking-tight leading-tight">
              Know your website’s <br className="hidden md:block" />
              <span className="text-primary-green">security posture.</span>
            </h1>
            <p className="text-secondary-text text-lg leading-relaxed max-w-2xl mx-auto">
              Sentinel Zero provides a professional, passive security analysis of your
              HTTPS certificates, security headers, and cookie attributes without
              interacting destructively with your server.
            </p>
          </div>

          <form onSubmit={handleScan} className="relative max-w-2xl mx-auto">
            <div className="flex items-center gap-3 p-2 bg-surface border border-subtle-border rounded-xl shadow-sm focus-within:border-primary-green transition-all">
              <div className="pl-3 text-secondary-text">
                <Search className="w-5 h-5" />
              </div>
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com"
                className="w-full bg-transparent border-none outline-none py-3 px-2 text-main-text placeholder:text-secondary-text text-lg"
                disabled={isLoading}
              />
              <button
                type="submit"
                disabled={isLoading}
                className="bg-primary-green text-white font-semibold py-3 px-8 rounded-lg hover:bg-deep-forest transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
              >
                {isLoading && <Loader2 className="w-4 h-4 animate-spin" />}
                {isLoading ? 'Analyzing...' : 'Analyze website'}
              </button>
            </div>
          </form>

          {error && (
            <div className="flex items-center gap-3 p-4 rounded-lg bg-red-50 border border-red-100 text-red-600 text-sm max-w-md mx-auto animate-in fade-in slide-in-from-top-2">
              <AlertCircle className="w-5 h-5 shrink-0" />
              <p>{error}</p>
            </div>
          )}
        </section>

        {report ? (
          <div className="space-y-10 animate-in fade-in slide-in-from-bottom-4 duration-500">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="p-6 rounded-xl bg-surface border border-subtle-border space-y-1 shadow-sm">
                <p className="text-secondary-text text-[11px] uppercase font-bold tracking-widest">Target URL</p>
                <p className="text-main-text font-medium truncate" title={report.target_url}>{report.target_url}</p>
              </div>
              <div className="p-6 rounded-xl bg-surface border border-subtle-border space-y-1 shadow-sm">
                <p className="text-secondary-text text-[11px] uppercase font-bold tracking-widest">Resolved IP</p>
                <p className="text-main-text font-medium">{report.validated_ip}</p>
              </div>
              <div className="p-6 rounded-xl bg-surface border border-subtle-border space-y-1 shadow-sm">
                <p className="text-secondary-text text-[11px] uppercase font-bold tracking-widest">Total Findings</p>
                <p className="text-main-text font-medium">{report.findings.length}</p>
              </div>
            </div>

            <div className="bg-surface border border-subtle-border rounded-2xl overflow-hidden shadow-sm">
              <div className="px-6 py-5 border-b border-subtle-border bg-slate-50/50 flex items-center justify-between">
                <h3 className="text-lg font-bold text-main-text">Detailed Security Findings</h3>
                {report.findings.length === 0 && (
                  <span className="flex items-center gap-2 text-xs text-primary-green font-medium px-3 py-1 rounded-full bg-pale-sage border border-primary-green/20">
                    <CheckCircle2 className="w-3 h-3" /> No findings detected
                  </span>
                )}
              </div>
              <div className="divide-y divide-subtle-border">
                {report.findings.length === 0 ? (
                  <div className="p-16 text-center space-y-3">
                    <p className="text-secondary-text text-lg">No vulnerabilities were detected in this passive scan.</p>
                    <p className="text-sm text-secondary-text/70 italic">Note: This does not guarantee the site is completely secure.</p>
                  </div>
                ) : (
                  report.findings.map((finding, idx) => (
                    <div key={idx} className="p-8 hover:bg-slate-50/50 transition-colors">
                      <div className="flex flex-col md:flex-row md:items-start justify-between gap-6">
                        <div className="space-y-3">
                          <div className="flex items-center gap-3">
                            <span className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${
                              finding.severity === 'critical' ? 'bg-critical/10 text-critical border-critical/20' :
                              finding.severity === 'high' ? 'bg-high/10 text-high border-high/20' :
                              finding.severity === 'medium' ? 'bg-medium/10 text-medium border-medium/20' :
                              finding.severity === 'low' ? 'bg-low/10 text-low border-low/20' :
                              'bg-info/10 text-info border-info/20'
                            }`}>
                              {finding.severity}
                            </span>
                            <h4 className="text-main-text font-bold text-lg">{finding.title}</h4>
                          </div>
                          <p className="text-secondary-text text-sm leading-relaxed max-w-3xl">{finding.explanation}</p>
                        </div>
                      </div>
                      {finding.evidence && (
                        <div className="mt-4 p-4 rounded-lg bg-slate-100 border border-subtle-border font-mono text-xs text-main-text overflow-x-auto">
                          <span className="text-secondary-text mr-2">Evidence:</span> {finding.evidence}
                        </div>
                      )}
                      <div className="mt-4 flex items-center gap-2 text-sm text-secondary-text italic">
                        <span className="text-main-text font-semibold not-italic">Remediation:</span> {finding.remediation}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        ) : (
          !isLoading && (
            <section className="border-2 border-dashed border-subtle-border rounded-3xl p-20 text-center space-y-4 bg-surface shadow-sm">
              <div className="flex justify-center mb-6">
                <div className="p-6 bg-slate-50 rounded-full">
                  <ShieldAlert className="w-16 h-16 text-slate-300" />
                </div>
              </div>
              <h2 className="text-2xl font-bold text-main-text">Ready for Analysis</h2>
              <p className="text-secondary-text max-w-md mx-auto leading-relaxed">
                Enter a target URL above to begin a professional passive security scan of your website's posture.
              </p>
            </section>
          )
        )}
      </main>

      <Footer />
    </Layout>
  );
};
