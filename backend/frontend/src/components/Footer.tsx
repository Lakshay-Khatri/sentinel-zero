import { AlertTriangle } from 'lucide-react';

const CURRENT_YEAR = new Date().getFullYear();

const LIMITATIONS = [
  'One ordinary request is made to the address you enter. Nothing is attacked, guessed or brute-forced.',
  'Only the HTTPS connection, security headers and cookie attributes are checked. Page content is not downloaded.',
  'The TLS check sees the one protocol version the server chose, not every version it supports.',
  'Cookie severity is estimated from the cookie name, because a passive scan cannot see what a cookie stores.',
  'Redirects are not followed. If the address redirects, the results describe the redirect response.',
];

export const Footer = () => {
  return (
    <footer className="mt-auto border-t border-subtle-border bg-surface px-4 py-10 sm:px-6">
      <div className="mx-auto max-w-4xl space-y-6">
        <section aria-labelledby="limits-heading" className="space-y-2">
          <h2 id="limits-heading" className="text-sm font-bold text-main-text">What this scan checks, and what it does not</h2>
          <ul className="list-disc space-y-1 pl-5 text-sm text-secondary-text">
            {LIMITATIONS.map((item) => <li key={item}>{item}</li>)}
          </ul>
        </section>

        <div className="flex items-start gap-3 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-800">
          <AlertTriangle className="h-5 w-5 shrink-0" aria-hidden="true" />
          <p className="font-medium">
            Authorization Notice: Scan only websites you own or have explicit permission to assess.
            Unauthorized scanning may violate terms of service or legal regulations.
          </p>
        </div>

        <div className="text-center text-xs text-secondary-text">
          <p>© {CURRENT_YEAR} Sentinel Zero Passive Analyzer</p>
          <p className="mt-1">
            A report with no findings does not guarantee that a website is completely secure.
          </p>
        </div>
      </div>
    </footer>
  );
};
