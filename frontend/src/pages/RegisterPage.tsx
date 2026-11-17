import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, Lock, Mail, User, AlertCircle, ArrowRight, Eye, EyeOff, CheckCircle2 } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { ApiRequestError } from '../services/api';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';

export const RegisterPage: React.FC = () => {
  const { register, login, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  React.useEffect(() => {
    if (isAuthenticated) {
      navigate('/', { replace: true });
    }
  }, [isAuthenticated, navigate]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    if (displayName.trim().length < 2) {
      setErrorMessage('Display name must be at least 2 characters long');
      return;
    }
    if (!email.trim()) {
      setErrorMessage('Please provide a valid email address');
      return;
    }
    if (password.length < 8) {
      setErrorMessage('Password must be at least 8 characters long');
      return;
    }
    if (password !== confirmPassword) {
      setErrorMessage('Passwords do not match');
      return;
    }

    setIsSubmitting(true);
    try {
      // 1. Register account
      await register({
        display_name: displayName.trim(),
        email: email.trim().toLowerCase(),
        password,
      });

      // 2. Automatically log in to establish session
      await login({
        email: email.trim().toLowerCase(),
        password,
      });

      navigate('/', { replace: true });
    } catch (err: any) {
      if (err instanceof ApiRequestError) {
        setErrorMessage(err.message);
      } else {
        setErrorMessage('Failed to register. Please check your network connection.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col justify-center items-center px-4 bg-[var(--color-bg)] text-[var(--color-text-primary)]">
      <div className="w-full max-w-md">
        {/* Brand header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-[var(--color-accent)]/15 border border-[var(--color-accent)]/40 text-[var(--color-accent)] mb-4">
            <Shield className="w-6 h-6" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-[var(--color-text-primary)]">
            Create Sentinel<span className="text-[var(--color-accent)]">RAG</span> Account
          </h1>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1.5">
            Enterprise-grade secure document intelligence
          </p>
        </div>

        {/* Card */}
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6 md:p-8 shadow-xl">
          {errorMessage && (
            <div className="mb-6 p-3.5 rounded-lg border border-[var(--color-danger)]/30 bg-[var(--color-danger)]/10 flex items-start gap-3 text-xs text-[var(--color-danger)]">
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>{errorMessage}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Display Name */}
            <div>
              <label htmlFor="displayName" className="block text-xs font-medium text-[var(--color-text-secondary)] uppercase tracking-wider mb-1.5">
                Full Name / Display Name
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[var(--color-text-secondary)]">
                  <User className="w-4 h-4" />
                </div>
                <input
                  id="displayName"
                  type="text"
                  required
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="Security Analyst"
                  className="w-full pl-9 pr-3 py-2 bg-[var(--color-surface-raised)] border border-[var(--color-border)] rounded-lg text-sm text-[var(--color-text-primary)] placeholder-[var(--color-text-secondary)]/50 focus:border-[var(--color-accent)] focus:outline-hidden transition-colors"
                />
              </div>
            </div>

            {/* Email */}
            <div>
              <label htmlFor="email" className="block text-xs font-medium text-[var(--color-text-secondary)] uppercase tracking-wider mb-1.5">
                Email Address
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[var(--color-text-secondary)]">
                  <Mail className="w-4 h-4" />
                </div>
                <input
                  id="email"
                  type="email"
                  autoComplete="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@domain.com"
                  className="w-full pl-9 pr-3 py-2 bg-[var(--color-surface-raised)] border border-[var(--color-border)] rounded-lg text-sm text-[var(--color-text-primary)] placeholder-[var(--color-text-secondary)]/50 focus:border-[var(--color-accent)] focus:outline-hidden transition-colors"
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <label htmlFor="password" className="block text-xs font-medium text-[var(--color-text-secondary)] uppercase tracking-wider mb-1.5">
                Password (min 8 chars)
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[var(--color-text-secondary)]">
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="new-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full pl-9 pr-10 py-2 bg-[var(--color-surface-raised)] border border-[var(--color-border)] rounded-lg text-sm text-[var(--color-text-primary)] placeholder-[var(--color-text-secondary)]/50 focus:border-[var(--color-accent)] focus:outline-hidden transition-colors"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Confirm Password */}
            <div>
              <label htmlFor="confirmPassword" className="block text-xs font-medium text-[var(--color-text-secondary)] uppercase tracking-wider mb-1.5">
                Confirm Password
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[var(--color-text-secondary)]">
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  id="confirmPassword"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="new-password"
                  required
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full pl-9 pr-3 py-2 bg-[var(--color-surface-raised)] border border-[var(--color-border)] rounded-lg text-sm text-[var(--color-text-primary)] placeholder-[var(--color-text-secondary)]/50 focus:border-[var(--color-accent)] focus:outline-hidden transition-colors"
                />
              </div>
            </div>

            {/* Password strength hints */}
            <div className="space-y-1 text-[11px] text-[var(--color-text-secondary)] pt-1">
              <div className="flex items-center gap-1.5">
                <CheckCircle2 className={`w-3 h-3 ${password.length >= 8 ? 'text-[var(--color-success)]' : 'text-[var(--color-text-secondary)]/40'}`} />
                <span>At least 8 characters</span>
              </div>
              <div className="flex items-center gap-1.5">
                <CheckCircle2 className={`w-3 h-3 ${/[a-zA-Z]/.test(password) && /[0-9!@#$%^&*]/.test(password) ? 'text-[var(--color-success)]' : 'text-[var(--color-text-secondary)]/40'}`} />
                <span>Letters & numbers/symbols</span>
              </div>
            </div>

            {/* Submit button */}
            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full mt-4 py-2.5 px-4 rounded-lg bg-[var(--color-accent)] hover:bg-[var(--color-accent-hover)] text-[var(--color-bg)] font-semibold text-sm flex items-center justify-center gap-2 transition-colors cursor-pointer disabled:opacity-60 shadow-sm"
            >
              {isSubmitting ? (
                <LoadingSpinner size="sm" label="Creating Account..." />
              ) : (
                <>
                  <span>Create Account</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Login link */}
          <div className="mt-6 pt-5 border-t border-[var(--color-border)] text-center text-xs text-[var(--color-text-secondary)]">
            Already have an account?{' '}
            <Link
              to="/login"
              className="text-[var(--color-accent)] hover:underline font-medium"
            >
              Sign In
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

