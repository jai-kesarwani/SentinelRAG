/**
 * SentinelRAG — TypeScript Type Definitions.
 * Matches backend schemas in app/schemas/health.py, app/schemas/auth.py, and design system.
 */

export interface ApiResponse<T> {
  data: T;
  meta: {
    correlation_id: string;
  };
}

export interface ApiErrorDetail {
  code: string;
  message: string;
  correlation_id: string;
}

export interface ApiError {
  error: ApiErrorDetail;
}

export type ServiceHealthState = 'healthy' | 'unhealthy' | 'degraded' | 'unknown';

export interface AppHealthData {
  status: ServiceHealthState;
  version: string;
  environment: string;
  timestamp: string;
}

export interface DatabaseHealthData {
  service: 'mongodb';
  status: ServiceHealthState;
  latency_ms: number | null;
  timestamp: string;
  error?: string;
}

export interface VectorStoreHealthData {
  service: 'chromadb';
  status: ServiceHealthState;
  latency_ms: number | null;
  collections: string[];
  timestamp: string;
  error?: string;
}

export interface PingData {
  pong: boolean;
  timestamp: string;
}

export interface NavItem {
  id: string;
  label: string;
  path: string;
  iconName: 'LayoutDashboard' | 'FileText' | 'MessageSquare' | 'Shield' | 'FlaskConical' | 'Settings';
  phaseTag?: string;
  isPlaceholder?: boolean;
}

// ------------------------------------------------------------------ //
// Phase 2: Authentication Types
// ------------------------------------------------------------------ //

export interface UserProfile {
  id: string;
  email: string;
  display_name: string;
  role: 'user' | 'admin';
  status: 'active' | 'suspended';
  created_at: string;
  last_login_at?: string | null;
}

export interface AuthTokens {
  access_token: string;
  token_type: string;
  expires_in_seconds: number;
  user: UserProfile;
}

export interface UserRegisterPayload {
  email: string;
  password: string;
  display_name: string;
}

export interface UserLoginPayload {
  email: string;
  password: string;
}

export interface LogoutResponseData {
  revoked: boolean;
  message: string;
}


// ------------------------------------------------------------------ //
// Phase 3: Document Management Types
// ------------------------------------------------------------------ //

export type DocumentStatus =
  | 'uploaded'
  | 'processing'
  | 'indexed'
  | 'review'
  | 'quarantined'
  | 'failed'
  | 'deleting'
  | 'deleted';

export interface DocumentTrustInfo {
  status: 'allow' | 'review' | 'quarantined';
  risk_level: 'low' | 'medium' | 'high';
  signals: string[];
  policy_decision: string;
}

export interface DocumentItem {
  id: string;
  _id?: string;
  owner_id: string;
  original_filename: string;
  file_size_bytes: number;
  mime_type: string;
  status: DocumentStatus;
  page_count: number;
  chunk_count: number;
  sha256: string;
  error_message?: string | null;
  trust?: DocumentTrustInfo;
  created_at: string;
  updated_at: string;
}

export interface DocumentListResponseData {
  documents: DocumentItem[];
  total: number;
}

export interface DocumentDeleteResponseData {
  document_id: string;
  deleted: boolean;
  chunks_deleted: number;
  message: string;
}


// ------------------------------------------------------------------ //
// Phase 4: Chat & RAG Types
// ------------------------------------------------------------------ //

export interface Citation {
  document_id: string;
  chunk_id: string;
  page_number: number;
  source_filename: string;
  excerpt?: string | null;
}

export interface ChatMessage {
  id: string;
  conversation_id: string;
  role: 'user' | 'assistant';
  content: string;
  citations: Citation[];
  created_at: string;
  validation_status: 'validated' | 'unsupported' | 'rejected';
}

export interface Conversation {
  id: string;
  title: string;
  owner_id: string;
  created_at: string;
  updated_at: string;
}

export interface ConversationListResponseData {
  conversations: Conversation[];
  total: number;
}

export interface ConversationDetailResponseData {
  conversation: Conversation;
  messages: ChatMessage[];
}

export interface ChatAnswerResponseData {
  message: ChatMessage;
  citations: Citation[];
  retrieved_chunk_count: number;
  grounded: boolean;
  confidence?: 'high' | 'low' | 'unsupported';
  security_decision?: 'allow' | 'block' | 'sanitize' | string;
  is_blocked?: boolean;
  blocked_reason?: string | null;
  safe_summary?: string | null;
}


// ------------------------------------------------------------------ //
// Phase 5: Document Security Inspection Types
// ------------------------------------------------------------------ //

export interface SecuritySignal {
  signal_id: string;
  category: string;
  pattern_name: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: 'low' | 'medium' | 'high';
  page_number: number;
  matched_snippet: string;
  description: string;
}

export interface DocumentSecurityDetails {
  document_id: string;
  original_filename: string;
  status: string;
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  policy_decision: 'allow' | 'review' | 'quarantined';
  signals_count: number;
  signals: SecuritySignal[];
  scanner_version: string;
  scanned_at?: string | null;
  summary: string;
}

export interface DocumentReviewPayload {
  decision: 'approve' | 'quarantine';
  notes?: string;
}

export interface DocumentReviewResponseData {
  document_id: string;
  status: string;
  policy_decision: string;
  chunk_count: number;
  message: string;
}

export interface DocumentRescanResponseData {
  document_id: string;
  risk_level: string;
  policy_decision: string;
  signals_count: number;
  summary: string;
  message: string;
}


// ------------------------------------------------------------------ //
// Phase 7: Attack Simulator Lab Types
// ------------------------------------------------------------------ //

export type AttackCategory =
  | 'direct_prompt_injection'
  | 'system_prompt_extraction'
  | 'indirect_prompt_injection'
  | 'data_exfiltration'
  | 'cross_tenant_access'
  | 'obfuscated_injection'
  | 'credential_canary_leakage'
  | 'malicious_output';

export type SimulationVerdict =
  | 'blocked'
  | 'detected_not_blocked'
  | 'attack_succeeded'
  | 'inconclusive'
  | 'error';

export interface AttackScenario {
  scenario_id: string;
  name: string;
  description: string;
  category: AttackCategory | string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  attack_type: 'query_inspection' | 'document_inspection' | 'retrieval_guard' | 'output_inspection' | 'end_to_end_rag' | string;
  input_payload: string;
  expected_behavior: string;
  expected_decision: string;
  enabled: boolean;
  created_at: string;
}

export interface ScenarioExecutionResult {
  scenario_id: string;
  scenario_name: string;
  category: string;
  severity: string;
  attack_type: string;
  input_payload_summary: string;
  expected_behavior: string;
  actual_decision: string;
  verdict: SimulationVerdict;
  verdict_reason: string;
  security_event_id?: string | null;
  duration_ms: number;
  signals_detected: Array<Record<string, any>>;
  execution_timestamp: string;
  error_details?: string | null;
}

export interface SimulationRunSummary {
  total_executed: number;
  blocked: number;
  detected_not_blocked: number;
  attack_succeeded: number;
  inconclusive: number;
  error: number;
  block_rate_percent: number;
}

export interface SimulationRun {
  id: string;
  owner_id: string;
  status: string;
  scenarios_count: number;
  results: ScenarioExecutionResult[];
  summary: SimulationRunSummary;
  duration_ms: number;
  created_at: string;
}

export interface SimulationStats {
  total_runs: number;
  total_executed: number;
  blocked: number;
  detected_not_blocked: number;
  attack_succeeded: number;
  inconclusive: number;
  error: number;
  block_rate_percent: number;
}


// ------------------------------------------------------------------ //
// Phase 8: Security Center & Analytics Types
// ------------------------------------------------------------------ //

export interface SecurityOverviewMetrics {
  total_events: number;
  blocked_queries: number;
  document_threats_detected: number;
  output_interventions: number;
  total_simulations: number;
  simulated_attacks_prevented: number;
  simulated_attacks_succeeded: number;
  simulation_block_rate_percent: number;
}

export interface TimelineDataPoint {
  timestamp: string;
  label: string;
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface SecurityActivityData {
  time_range: string;
  total_events: number;
  timeline: TimelineDataPoint[];
}

export interface CategoryCount {
  category: string;
  label: string;
  count: number;
  percentage: number;
}

export interface SeverityCount {
  severity: string;
  count: number;
  percentage: number;
}

export interface ThreatDistributionData {
  total_events: number;
  categories: CategoryCount[];
  severities: SeverityCount[];
  decisions: Record<string, number>;
}

export interface SimulationCategoryStat {
  category: string;
  label: string;
  total: number;
  blocked: number;
  detected_not_blocked: number;
  attack_succeeded: number;
  inconclusive: number;
  error: number;
  block_rate_percent: number;
}

export interface SimulationAnalyticsData {
  total_runs: number;
  total_executed: number;
  completed_attacks: number;
  blocked: number;
  detected_not_blocked: number;
  attack_succeeded: number;
  inconclusive: number;
  error: number;
  block_rate_percent: number;
  categories: SimulationCategoryStat[];
}

export interface SecurityEventDetail {
  id: string;
  owner_id: string;
  event_type: string;
  category: string;
  severity: 'low' | 'medium' | 'high' | 'critical' | string;
  decision: 'allow' | 'block' | 'review' | 'quarantined' | 'sanitize' | string;
  reason_code: string;
  resource_type: string;
  resource_id?: string | null;
  detector: {
    name: string;
    version: string;
  };
  safe_metadata: Record<string, any>;
  correlation_id?: string | null;
  created_at: string;
}

export interface SecurityEventListResponseData {
  events: SecurityEventDetail[];
  total: number;
  limit: number;
  skip: number;
}
