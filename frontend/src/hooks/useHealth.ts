/**
 * SentinelRAG — Health Check Hook.
 * Polls backend health endpoints and manages live service status.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { healthApi } from '../services/api';
import type { AppHealthData, DatabaseHealthData, VectorStoreHealthData } from '../types';

export interface SystemHealthState {
  app: AppHealthData | null;
  database: DatabaseHealthData | null;
  vectorStore: VectorStoreHealthData | null;
  isLoading: boolean;
  isRefreshing: boolean;
  lastUpdated: Date | null;
  error: string | null;
}

export function useHealth(pollIntervalMs = 15000) {
  const [state, setState] = useState<SystemHealthState>({
    app: null,
    database: null,
    vectorStore: null,
    isLoading: true,
    isRefreshing: false,
    lastUpdated: null,
    error: null,
  });

  const isMountedRef = useRef(true);

  const fetchHealth = useCallback(async (isManualRefresh = false) => {
    setState((prev) => ({
      ...prev,
      isRefreshing: isManualRefresh,
      isLoading: prev.lastUpdated === null,
    }));

    try {
      const [appRes, dbRes, vectorRes] = await Promise.allSettled([
        healthApi.getAppHealth(),
        healthApi.getDatabaseHealth(),
        healthApi.getVectorStoreHealth(),
      ]);

      if (!isMountedRef.current) return;

      const app = appRes.status === 'fulfilled' ? appRes.value.data : null;
      const database = dbRes.status === 'fulfilled' ? dbRes.value.data : null;
      const vectorStore = vectorRes.status === 'fulfilled' ? vectorRes.value.data : null;

      let errorMsg: string | null = null;
      if (appRes.status === 'rejected') {
        errorMsg = (appRes.reason as Error)?.message || 'Failed to connect to API server';
      }

      setState({
        app,
        database,
        vectorStore,
        isLoading: false,
        isRefreshing: false,
        lastUpdated: new Date(),
        error: errorMsg,
      });
    } catch (err: any) {
      if (!isMountedRef.current) return;
      setState((prev) => ({
        ...prev,
        isLoading: false,
        isRefreshing: false,
        error: err.message || 'Unexpected error fetching system health',
      }));
    }
  }, []);

  useEffect(() => {
    isMountedRef.current = true;
    fetchHealth(false);

    if (pollIntervalMs > 0) {
      const intervalId = setInterval(() => {
        fetchHealth(false);
      }, pollIntervalMs);

      return () => {
        isMountedRef.current = false;
        clearInterval(intervalId);
      };
    }

    return () => {
      isMountedRef.current = false;
    };
  }, [fetchHealth, pollIntervalMs]);

  return {
    ...state,
    refetch: () => fetchHealth(true),
  };
}

