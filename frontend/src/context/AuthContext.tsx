/**
 * SentinelRAG — Centralized Authentication Context.
 * Manages user session state in memory and coordinates silent session refresh.
 */

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { authApi, clearAccessToken } from '../services/api';
import type { UserProfile, UserLoginPayload, UserRegisterPayload } from '../types';

interface AuthContextType {
  user: UserProfile | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (credentials: UserLoginPayload) => Promise<UserProfile>;
  register: (payload: UserRegisterPayload) => Promise<UserProfile>;
  logout: () => Promise<void>;
  refreshSession: () => Promise<UserProfile | null>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Silent session restore on initial application load
  const refreshSession = useCallback(async (): Promise<UserProfile | null> => {
    try {
      const res = await authApi.refresh();
      setUser(res.data.user);
      return res.data.user;
    } catch {
      // Refresh token missing or expired; clear in-memory state
      clearAccessToken();
      setUser(null);
      return null;
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshSession();
  }, [refreshSession]);

  const login = async (credentials: UserLoginPayload): Promise<UserProfile> => {
    const res = await authApi.login(credentials);
    setUser(res.data.user);
    return res.data.user;
  };

  const register = async (payload: UserRegisterPayload): Promise<UserProfile> => {
    const res = await authApi.register(payload);
    return res.data;
  };

  const logout = async (): Promise<void> => {
    try {
      await authApi.logout();
    } catch {
      // Proceed with local logout regardless of network error
    } finally {
      clearAccessToken();
      setUser(null);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        register,
        logout,
        refreshSession,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

