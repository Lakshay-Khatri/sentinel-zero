import { AlertTriangle } from 'lucide-react';

export const Footer = () => {
  return (
    <footer className="border-t border-subtle-border bg-surface px-6 py-10 mt-auto">
      <div className="max-w-4xl mx-auto space-y-6">
        <div className="flex items-start gap-3 p-4 rounded-lg bg-red-50 border border-red-100 text-red-700 text-sm">
          <AlertTriangle className="w-5 h-5 shrink-0" />
          <p className="font-medium">
            Authorization Notice: Scan only websites you own or have explicit permission to assess.
            Unauthorized scanning may violate terms of service or legal regulations.
          </p>
        </div>

        <div className="text-center text-secondary-text text-xs">
          <p>© {new Date().getFullYear()} Sentinel Zero Passive Analyzer</p>
          <p className="mt-1 italic">
            Disclaimer: A report with no findings does not guarantee that a website is completely secure.
          </p>
        </div>
      </div>
    </footer>
  );
};
