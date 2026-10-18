import React from 'react';

export const Layout = ({ children }: { children: React.ReactNode }) => {
  return (
    <div className="min-h-screen flex flex-col bg-warm-ivory text-main-text">
      {children}
    </div>
  );
};
