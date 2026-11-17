import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  FileText,
  MessageSquare,
  ShieldAlert,
  FlaskConical,
  Settings,
  X,
} from 'lucide-react';
import type { NavItem } from '../../types';

interface SidebarProps {
  isOpen: boolean;
  onClose: () => void;
}

const navItems: NavItem[] = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    path: '/',
    iconName: 'LayoutDashboard',
    isPlaceholder: false,
  },
  {
    id: 'documents',
    label: 'Documents',
    path: '/documents',
    iconName: 'FileText',
    phaseTag: 'Phase 3',
    isPlaceholder: false,
  },
  {
    id: 'chat',
    label: 'AI Assistant',
    path: '/chat',
    iconName: 'MessageSquare',
    phaseTag: 'Phase 4',
    isPlaceholder: false,
  },
  {
    id: 'security',
    label: 'Security Center',
    path: '/security-center',
    iconName: 'Shield',
    phaseTag: 'Phase 8',
    isPlaceholder: false,
  },
  {
    id: 'lab',
    label: 'Attack Simulator',
    path: '/simulator',
    iconName: 'FlaskConical',
    phaseTag: 'Phase 7',
    isPlaceholder: false,
  },
  {
    id: 'settings',
    label: 'Settings',
    path: '/settings',
    iconName: 'Settings',
    phaseTag: 'Phase 2',
    isPlaceholder: true,
  },
];

const renderIcon = (name: NavItem['iconName']) => {
  const iconProps = { className: 'w-5 h-5 flex-shrink-0' };
  switch (name) {
    case 'LayoutDashboard':
      return <LayoutDashboard {...iconProps} />;
    case 'FileText':
      return <FileText {...iconProps} />;
    case 'MessageSquare':
      return <MessageSquare {...iconProps} />;
    case 'Shield':
      return <ShieldAlert {...iconProps} />;
    case 'FlaskConical':
      return <FlaskConical {...iconProps} />;
    case 'Settings':
      return <Settings {...iconProps} />;
  }
};

export const Sidebar: React.FC<SidebarProps> = ({ isOpen, onClose }) => {
  return (
    <>
      {/* Mobile backdrop */}
      {isOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 md:hidden backdrop-blur-xs transition-opacity"
          onClick={onClose}
          aria-hidden="true"
        />
      )}

      {/* Sidebar container */}
      <aside
        className={`fixed top-0 bottom-0 left-0 z-50 flex flex-col w-64 bg-[var(--color-surface)] border-r border-[var(--color-border)] transition-transform duration-200 ease-in-out md:translate-x-0 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Brand header */}
        <div className="flex items-center justify-between h-16 px-5 border-b border-[var(--color-border)]">
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-[var(--color-accent)]/15 border border-[var(--color-accent)]/40 text-[var(--color-accent)]">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <span className="text-base font-bold tracking-tight text-[var(--color-text-primary)]">
                Sentinel<span className="text-[var(--color-accent)]">RAG</span>
              </span>
              <p className="text-[10px] uppercase font-mono tracking-wider text-[var(--color-text-secondary)]">
                Secure AI Agent
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="md:hidden p-1.5 rounded-md text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-raised)]"
            aria-label="Close sidebar"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Navigation list */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto" aria-label="Main Navigation">
          <div className="px-3 pb-2 text-[11px] font-semibold tracking-wider text-[var(--color-text-secondary)] uppercase">
            Platform
          </div>
          {navItems.map((item) => (
            <div key={item.id}>
              {item.isPlaceholder ? (
                <div
                  className="group flex items-center justify-between px-3 py-2 text-sm font-medium rounded-md text-[var(--color-text-secondary)]/60 cursor-not-allowed hover:bg-[var(--color-surface-raised)]/30 transition-colors"
                  title={`${item.label} (${item.phaseTag})`}
                >
                  <div className="flex items-center gap-3">
                    {renderIcon(item.iconName)}
                    <span>{item.label}</span>
                  </div>
                  {item.phaseTag && (
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--color-border)]/50 text-[var(--color-text-secondary)]">
                      {item.phaseTag}
                    </span>
                  )}
                </div>
              ) : (
                <NavLink
                  to={item.path}
                  onClick={() => {
                    if (window.innerWidth < 768) onClose();
                  }}
                  className={({ isActive }) =>
                    `flex items-center justify-between px-3 py-2 text-sm font-medium rounded-md transition-colors ${
                      isActive
                        ? 'bg-[var(--color-accent)]/15 text-[var(--color-accent)] border border-[var(--color-accent)]/30'
                        : 'text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-raised)]'
                    }`
                  }
                >
                  <div className="flex items-center gap-3">
                    {renderIcon(item.iconName)}
                    <span>{item.label}</span>
                  </div>
                </NavLink>
              )}
            </div>
          ))}
        </nav>

        {/* Footer brand tagline */}
        <div className="p-4 border-t border-[var(--color-border)] bg-[var(--color-surface-raised)]/30">
          <p className="text-xs font-medium text-[var(--color-text-primary)]">
            Intelligence. Protected.
          </p>
          <p className="text-[11px] text-[var(--color-text-secondary)] mt-0.5">
            Phase 1 Foundation
          </p>
        </div>
      </aside>
    </>
  );
};

