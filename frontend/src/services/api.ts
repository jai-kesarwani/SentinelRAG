/**
 * SentinelRAG — Centralized API Client Service.
 * Native fetch-based client with typed envelopes, in-memory token handling,
 * and HttpOnly cookie integration for session refresh.
 */

import type {
  ApiResponse,
  ApiError,
  AppHealthData,
  DatabaseHealthData,
  VectorStoreHealthData,
  PingData,
  UserProfile,
  AuthTokens,
  UserRegisterPayload,
  UserLoginPayload,
  LogoutResponseData,
  DocumentItem,
  DocumentListResponseData,
  DocumentDeleteResponseData,
  Conversation,
  ConversationListResponseData,
  ConversationDetailResponseData,
  ChatAnswerResponseData,
  DocumentSecurityDetails,
  DocumentReviewPayload,
  DocumentReviewResponseData,
  DocumentRescanResponseData,
  AttackScenario,
  SimulationRun,
  SimulationStats,
  SecurityOverviewMetrics,
  SecurityActivityData,
  ThreatDistributionData,
  SimulationAnalyticsData,
  SecurityEventDetail,
  SecurityEventListResponseData,
} from '../types';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '';

// Security: Keep access tokens strictly in memory (never localStorage)
let inMemoryAccessToken: string | null = null;

export function setAccessToken(token: string | null): void {
  inMemoryAccessToken = token;
}

export function getAccessToken(): string | null {
  return inMemoryAccessToken;
}

export function clearAccessToken(): void {
  inMemoryAccessToken = null;
}

export class ApiRequestError extends Error {
  code: string;
  correlationId?: string;
  statusCode?: number;

  constructor(message: string, code = 'REQUEST_FAILED', statusCode?: number, correlationId?: string) {
    super(message);
    this.name = 'ApiRequestError';
    this.code = code;
    this.statusCode = statusCode;
    this.correlationId = correlationId;
  }
}

export interface RequestOptions extends RequestInit {
  timeoutMs?: number;
}

async function request<T>(endpoint: string, options: RequestOptions = {}): Promise<ApiResponse<T>> {
  const url = `${API_BASE_URL}${endpoint}`;
  const isFormData = typeof FormData !== 'undefined' && options.body instanceof FormData;
  const isChatMessage = endpoint.includes('/chat/conversations/') && endpoint.endsWith('/messages');
  const controller = new AbortController();

  // Chat completions require a dedicated 120s timeout window for RAG retrieval + LLM inference
  const defaultTimeout = isChatMessage ? 120000 : (isFormData ? 60000 : 8000);
  const timeoutMs = options.timeoutMs ?? defaultTimeout;
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  // Link external abort signal if supplied by caller
  if (options.signal) {
    if (options.signal.aborted) {
      controller.abort();
    } else {
      options.signal.addEventListener('abort', () => controller.abort());
    }
  }

  const defaultHeaders: Record<string, string> = {
    'Accept': 'application/json',
  };

  // Only set Content-Type to application/json if not uploading FormData
  if (!isFormData) {
    defaultHeaders['Content-Type'] = 'application/json';
  }

  // Attach in-memory access token if present
  if (inMemoryAccessToken) {
    defaultHeaders['Authorization'] = `Bearer ${inMemoryAccessToken}`;
  }

  try {
    const response = await fetch(url, {
      ...options,
      headers: {
        ...defaultHeaders,
        ...(options.headers as Record<string, string>),
      },
      // Include cookies so HttpOnly refresh token is sent/received
      credentials: 'include',
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    const correlationId = response.headers.get('X-Correlation-ID') || '';
    let body: any;

    try {
      body = await response.json();
    } catch {
      throw new ApiRequestError(
        `Failed to parse server response from ${endpoint}`,
        'INVALID_RESPONSE',
        response.status,
        correlationId
      );
    }

    if (!response.ok) {
      const errorData = body as ApiError;
      throw new ApiRequestError(
        errorData?.error?.message || `Request failed with HTTP ${response.status}`,
        errorData?.error?.code || 'HTTP_ERROR',
        response.status,
        errorData?.error?.correlation_id || correlationId
      );
    }

    return body as ApiResponse<T>;
  } catch (error: any) {
    clearTimeout(timeoutId);
    if (error instanceof ApiRequestError) {
      throw error;
    }
    if (error.name === 'AbortError') {
      throw new ApiRequestError(
        `Request to ${endpoint} timed out after ${timeoutMs}ms`,
        'TIMEOUT'
      );
    }
    throw new ApiRequestError(
      error.message || 'Network error: could not connect to backend',
      'NETWORK_ERROR'
    );
  }
}

export const healthApi = {
  getAppHealth: () => request<AppHealthData>('/api/v1/health'),
  getDatabaseHealth: () => request<DatabaseHealthData>('/api/v1/health/database'),
  getVectorStoreHealth: () => request<VectorStoreHealthData>('/api/v1/health/vector-store'),
  ping: () => request<PingData>('/api/v1/ping'),
};

export const authApi = {
  register: (payload: UserRegisterPayload) =>
    request<UserProfile>('/api/v1/auth/register', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  login: async (payload: UserLoginPayload) => {
    const res = await request<AuthTokens>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    // Set in-memory access token
    setAccessToken(res.data.access_token);
    return res;
  },

  refresh: async () => {
    const res = await request<AuthTokens>('/api/v1/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({}),
    });
    setAccessToken(res.data.access_token);
    return res;
  },

  logout: async () => {
    try {
      return await request<LogoutResponseData>('/api/v1/auth/logout', {
        method: 'POST',
        body: JSON.stringify({}),
      });
    } finally {
      clearAccessToken();
    }
  },

  getMe: () => request<UserProfile>('/api/v1/auth/me'),
};


export const documentsApi = {
  upload: (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    return request<DocumentItem>('/api/v1/documents/upload', {
      method: 'POST',
      body: formData,
    });
  },

  list: (limit = 50, skip = 0) =>
    request<DocumentListResponseData>(`/api/v1/documents?limit=${limit}&skip=${skip}`),

  get: (id: string) => request<DocumentItem>(`/api/v1/documents/${id}`),

  getSecurityDetails: (id: string) =>
    request<DocumentSecurityDetails>(`/api/v1/documents/${id}/security`),

  review: (id: string, payload: DocumentReviewPayload) =>
    request<DocumentReviewResponseData>(`/api/v1/documents/${id}/review`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  rescan: (id: string) =>
    request<DocumentRescanResponseData>(`/api/v1/documents/${id}/rescan`, {
      method: 'POST',
    }),

  listReviewQueue: (limit = 50, skip = 0) =>
    request<DocumentListResponseData>(`/api/v1/documents/review/queue?limit=${limit}&skip=${skip}`),

  delete: (id: string) =>
    request<DocumentDeleteResponseData>(`/api/v1/documents/${id}`, {
      method: 'DELETE',
    }),
};


export const chatApi = {
  createConversation: (title?: string) =>
    request<Conversation>('/api/v1/chat/conversations', {
      method: 'POST',
      body: JSON.stringify(title ? { title } : {}),
    }),

  listConversations: (limit = 50, skip = 0) =>
    request<ConversationListResponseData>(`/api/v1/chat/conversations?limit=${limit}&skip=${skip}`),

  getConversation: (id: string) =>
    request<ConversationDetailResponseData>(`/api/v1/chat/conversations/${id}`),

  sendMessage: (conversationId: string, content: string) =>
    request<ChatAnswerResponseData>(`/api/v1/chat/conversations/${conversationId}/messages`, {
      method: 'POST',
      body: JSON.stringify({ content }),
      timeoutMs: 120000,
    }),

  deleteConversation: (id: string) =>
    request<{ conversation_id: string; deleted: boolean; message: string }>(
      `/api/v1/chat/conversations/${id}`,
      {
        method: 'DELETE',
      }
    ),
};


export const simulatorApi = {
  listScenarios: (category?: string) => {
    const query = category && category !== 'all' ? `?category=${encodeURIComponent(category)}` : '';
    return request<{ scenarios: AttackScenario[]; total: number }>(`/api/v1/simulator/scenarios${query}`);
  },

  getScenario: (id: string) =>
    request<AttackScenario>(`/api/v1/simulator/scenarios/${id}`),

  createRun: (payload: { scenario_ids?: string[]; category?: string }) =>
    request<SimulationRun>('/api/v1/simulator/runs', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  listRuns: (limit = 50, skip = 0) =>
    request<{ runs: SimulationRun[]; total: number }>(`/api/v1/simulator/runs?limit=${limit}&skip=${skip}`),

  getRun: (id: string) =>
    request<SimulationRun>(`/api/v1/simulator/runs/${id}`),

  deleteRun: (id: string) =>
    request<{ deleted: boolean; run_id: string }>(`/api/v1/simulator/runs/${id}`, {
      method: 'DELETE',
    }),

  getStats: () =>
    request<SimulationStats>('/api/v1/simulator/stats'),
};


export const securityCenterApi = {
  getOverview: (days?: number) => {
    const query = days ? `?days=${days}` : '';
    return request<SecurityOverviewMetrics>(`/api/v1/security-center/overview${query}`);
  },

  getActivity: (timeRange = '7d') =>
    request<SecurityActivityData>(`/api/v1/security-center/activity?time_range=${timeRange}`),

  getThreatDistribution: (days = 30) =>
    request<ThreatDistributionData>(`/api/v1/security-center/threat-distribution?days=${days}`),

  getSimulationAnalytics: () =>
    request<SimulationAnalyticsData>('/api/v1/security-center/simulation-analytics'),

  listEvents: (params?: {
    category?: string;
    severity?: string;
    decision?: string;
    event_type?: string;
    search?: string;
    days?: number;
    limit?: number;
    skip?: number;
  }) => {
    const queryParts: string[] = [];
    if (params) {
      if (params.category && params.category !== 'all') queryParts.push(`category=${encodeURIComponent(params.category)}`);
      if (params.severity && params.severity !== 'all') queryParts.push(`severity=${encodeURIComponent(params.severity)}`);
      if (params.decision && params.decision !== 'all') queryParts.push(`decision=${encodeURIComponent(params.decision)}`);
      if (params.event_type) queryParts.push(`event_type=${encodeURIComponent(params.event_type)}`);
      if (params.search) queryParts.push(`search=${encodeURIComponent(params.search)}`);
      if (params.days) queryParts.push(`days=${params.days}`);
      if (params.limit !== undefined) queryParts.push(`limit=${params.limit}`);
      if (params.skip !== undefined) queryParts.push(`skip=${params.skip}`);
    }
    const queryString = queryParts.length > 0 ? `?${queryParts.join('&')}` : '';
    return request<SecurityEventListResponseData>(`/api/v1/security-center/events${queryString}`);
  },

  getEventDetail: (eventId: string) =>
    request<SecurityEventDetail>(`/api/v1/security-center/events/${eventId}`),
};
