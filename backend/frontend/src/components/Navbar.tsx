import { Shield, Activity, Loader2 } from 'lucide-react';

export const Navbar = ({ isOnline, isChecking }: { isOnline: boolean; isChecking: boolean }) => {
  return (
    <nav className="border-b border-subtle-border bg-surface px-6 py-4 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <div className="p-1.5 bg-pale-sage rounded-md">
          <Shield className="text-deep-forest w-5 h-5" />
        </div>
        <span className="text-lg font-semibold tracking-tight text-main-text">
          Sentinel <span className="text-primary-green">Zero</span>
        </span>
      </div>

      <div className="flex items-center gap-2 px-3 py-1 rounded-full border border-subtle-border bg-warm-ivory text-[11px] font-medium">
        {isChecking ? (
          <>
            <Loader2 className="w-3 h-3 animate-spin text-secondary-text" />
            <span className="text-secondary-text">Checking...</span>
          </>
        ) : (
          <>
            <Activity className={`w-3 h-3 ${isOnline ? 'text-primary-green' : 'text-critical'}`} />
            <span className={isOnline ? 'text-primary-green' : 'text-critical'}>
              {isOnline ? 'System Operational' : 'System Offline'}
            </span>
          </>
        )}
      </div>
    </nav>
  );
};
