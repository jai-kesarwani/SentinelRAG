import React, { useState } from 'react';
import { Sidebar } from '../components/layout/Sidebar';
import { Topbar } from '../components/layout/Topbar';

interface AppLayoutProps {
  children?: React.ReactNode;
  pageTitle?: string;
  pageSubtitle?: string;
}

export const AppLayout: React.FC<AppLayoutProps> = ({
  children,
  pageTitle = 'Dashboard',
  pageSubtitle = 'System Foundation & Verification',
}) => {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div className="min-h-screen flex bg-[var(--color-bg)] text-[var(--color-text-primary)]">
      {/* Sidebar navigation */}
      <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      {/* Main content wrapper */}
      <div className="flex-1 flex flex-col md:pl-64 min-w-0">
        <Topbar
          onMenuClick={() => setSidebarOpen(true)}
          title={pageTitle}
          subtitle={pageSubtitle}
          environment={import.meta.env.VITE_APP_ENV || 'development'}
        />

        {/* Content area */}
        <main className="flex-1 p-4 md:p-8 max-w-7xl w-full mx-auto">
          {children}
        </main>
      </div>
    </div>
  );
};

