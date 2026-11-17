import React, { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { Shield, Lock, Mail, AlertCircle, ArrowRight, Eye, EyeOff } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { ApiRequestError } from '../services/api';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';

export const LoginPage: React.FC = () => {
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // If already logged in, redirect to dashboard
  React.useEffect(() => {
    if (isAuthenticated) {
      const from = (location.state as any)?.from?.pathname || '/';
      navigate(from, { replace: true });
    }
  }, [isAuthenticated, navigate, location]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    if (!email.trim() || !password) {
      setErrorMessage('Please enter both email and password');
      return;
    }

    setIsSubmitting(true);
    try {
      await login({ email: email.trim(), password });
      const from = (location.state as any)?.from?.pathname || '/';
      navigate(from, { replace: true });
    } catch (err: any) {
      if (err instanceof ApiRequestError) {
        setErrorMessage(err.message);
      } else {
        setErrorMessage('Failed to sign in. Please verify your connection.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col justify-center items-center px-4 bg-[var(--color-bg)] text-[var(--color-text-primary)]">
      <div className="w-full max-w-md">
        {/* Brand logo & title */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-[var(--color-accent)]/15 border border-[var(--color-accent)]/40 text-[var(--color-accent)] mb-4">
            <Shield className="w-6 h-6" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-[var(--color-text-primary)]">
            Sign In to Sentinel<span className="text-[var(--color-accent)]">RAG</span>
          </h1>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1.5">
            Secure Retrieval-Augmented Generation Agent
          </p>
        </div>

        {/* Login card */}
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6 md:p-8 shadow-xl">
          {errorMessage && (
            <div className="mb-6 p-3.5 rounded-lg border border-[var(--color-danger)]/30 bg-[var(--color-danger)]/10 flex items-start gap-3 text-xs text-[var(--color-danger)]">
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>{errorMessage}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Email Field */}
            <div>
              <label htmlFor="email" className="block text-xs font-medium text-[var(--color-text-secondary)] uppercase tracking-wider mb-2">
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
                  placeholder="name@organization.com"
                  className="w-full pl-9 pr-3 py-2.5 bg-[var(--color-surface-raised)] border border-[var(--color-border)] rounded-lg text-sm text-[var(--color-text-primary)] placeholder-[var(--color-text-secondary)]/50 focus:border-[var(--color-accent)] focus:outline-hidden transition-colors"
                />
              </div>
            </div>

            {/* Password Field */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <label htmlFor="password" className="block text-xs font-medium text-[var(--color-text-secondary)] uppercase tracking-wider">
                  Password
                </label>
              </div>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[var(--color-text-secondary)]">
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full pl-9 pr-10 py-2.5 bg-[var(--color-surface-raised)] border border-[var(--color-border)] rounded-lg text-sm text-[var(--color-text-primary)] placeholder-[var(--color-text-secondary)]/50 focus:border-[var(--color-accent)] focus:outline-hidden transition-colors"
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

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full py-2.5 px-4 rounded-lg bg-[var(--color-accent)] hover:bg-[var(--color-accent-hover)] text-[var(--color-bg)] font-semibold text-sm flex items-center justify-center gap-2 transition-colors cursor-pointer disabled:opacity-60 shadow-sm"
            >
              {isSubmitting ? (
                <LoadingSpinner size="sm" label="Authenticating..." />
              ) : (
                <>
                  <span>Sign In</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Registration link */}
          <div className="mt-6 pt-6 border-t border-[var(--color-border)] text-center text-xs text-[var(--color-text-secondary)]">
            Don't have an account?{' '}
            <Link
              to="/register"
              className="text-[var(--color-accent)] hover:underline font-medium"
            >
              Create Account
            </Link>
          </div>
        </div>

        {/* Security badge footer */}
        <p className="mt-8 text-center text-xs text-[var(--color-text-secondary)]/60">
          Argon2id Password Hashing • Server-Side JWT Validation
        </p>
      </div>
    </div>
  );
};

