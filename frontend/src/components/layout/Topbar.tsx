import React from 'react';
import { Menu, ShieldCheck, LogOut, User } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

interface TopbarProps {
  onMenuClick: () => void;
  title: string;
  subtitle?: string;
  environment?: string;
}

export const Topbar: React.FC<TopbarProps> = ({
  onMenuClick,
  title,
  subtitle,
  environment = 'DEV',
}) => {
  const { user, logout } = useAuth();

  const handleLogout = async () => {
    await logout();
  };

  const getInitials = (name?: string) => {
    if (!name) return 'U';
    const parts = name.trim().split(' ');
    if (parts.length >= 2) {
      return `${parts[0][0]}${parts[1][0]}`.toUpperCase();
    }
    return name.slice(0, 2).toUpperCase();
  };

  return (
    <header className="sticky top-0 z-30 flex items-center justify-between h-16 px-4 md:px-8 bg-[var(--color-surface)]/95 border-b border-[var(--color-border)] backdrop-blur-xs">
      {/* Left: Mobile hamburger & breadcrumbs */}
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={onMenuClick}
          className="p-2 -ml-2 rounded-md md:hidden text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-raised)]"
          aria-label="Open sidebar"
        >
          <Menu className="w-5 h-5" />
        </button>
        <div>
          <h1 className="text-lg font-semibold text-[var(--color-text-primary)] leading-tight">
            {title}
          </h1>
          {subtitle && (
            <p className="text-xs text-[var(--color-text-secondary)]">
              {subtitle}
            </p>
          )}
        </div>
      </div>

      {/* Right: Environment badge & profile info */}
      <div className="flex items-center gap-3">
        {/* Environment pill */}
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-medium bg-[var(--color-warning)]/10 border border-[var(--color-warning)]/30 text-[var(--color-warning)]">
          <span className="w-1.5 h-1.5 rounded-full bg-[var(--color-warning)]" />
          <span>{environment.toUpperCase()}</span>
        </div>

        {/* Security indicator pill */}
        <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-[var(--color-success)]/10 border border-[var(--color-success)]/30 text-[var(--color-success)]">
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>Gateway Active</span>
        </div>

        {/* User profile & Logout */}
        {user ? (
          <div className="flex items-center gap-2.5 pl-2 border-l border-[var(--color-border)]">
            <div className="flex items-center gap-2">
              <div
                className="flex items-center justify-center w-8 h-8 rounded-full bg-[var(--color-accent)]/15 border border-[var(--color-accent)]/40 text-[var(--color-accent)] text-xs font-semibold"
                title={`${user.display_name} (${user.email})`}
              >
                {getInitials(user.display_name)}
              </div>
              <div className="hidden lg:block text-left">
                <p className="text-xs font-semibold text-[var(--color-text-primary)] leading-tight">
                  {user.display_name}
                </p>
                <p className="text-[10px] text-[var(--color-text-secondary)] font-mono capitalize">
                  {user.role}
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={handleLogout}
              className="p-1.5 rounded-md text-[var(--color-text-secondary)] hover:text-[var(--color-danger)] hover:bg-[var(--color-danger)]/10 transition-colors cursor-pointer"
              title="Sign Out"
              aria-label="Sign Out"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        ) : (
          <div
            className="flex items-center justify-center w-8 h-8 rounded-full bg-[var(--color-surface-raised)] border border-[var(--color-border)] text-[var(--color-text-primary)] text-xs font-semibold"
            title="Guest"
          >
            <User className="w-4 h-4 text-[var(--color-text-secondary)]" />
          </div>
        )}
      </div>
    </header>
  );
};
