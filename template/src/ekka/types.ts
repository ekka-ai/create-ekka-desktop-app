/**
 * EKKA Type Definitions
 *
 * Central type definitions for the EKKA client library.
 * All interfaces, types, and type aliases are defined here.
 * Also includes contract helper functions.
 */

import { CONTRACT_VERSION } from './constants';

// =============================================================================
// CONTRACT TYPES
// =============================================================================

/**
 * Request format for all engine operations.
 */
export interface EngineRequest {
  /** Operation name, e.g. "db.get", "queue.enqueue", "runtime.info" */
  op: string;
  /** Contract version */
  v: number;
  /** Operation-specific payload */
  payload: unknown;
  /** Correlation ID for request tracking */
  correlationId: string;
}

/**
 * Error detail in response.
 */
export interface EngineErrorDetail {
  code: string;
  message: string;
  details?: unknown;
}

/**
 * Response format for all engine operations.
 */
export interface EngineResponse {
  ok: boolean;
  result?: unknown;
  error?: EngineErrorDetail;
}

// =============================================================================
// RUNTIME TYPES
// =============================================================================

/**
 * Runtime environment type.
 */
export type RuntimeType = 'web' | 'tauri';

/**
 * Transport mode - determines which backend handles requests.
 */
export type TransportMode = 'demo' | 'engine';

/**
 * Runtime information returned by the system.
 */
export interface RuntimeInfo {
  runtime: RuntimeType;
  engine_present: boolean;
}

// =============================================================================
// SESSION TYPES
// =============================================================================

/**
 * Session state information.
 */
export interface SessionInfo {
  connected: boolean;
}

// =============================================================================
// API TYPES
// =============================================================================

/**
 * Job in the queue.
 */
export interface Job<T = unknown> {
  id: string;
  kind: string;
  payload: T;
  created_at: string;
}

/**
 * Internal job representation with claim state.
 */
export interface QueuedJob<T = unknown> extends Job<T> {
  claimed: boolean;
}

// =============================================================================
// CONTRACT HELPERS
// =============================================================================

/**
 * Generate a correlation ID (UUID v4) for request tracking.
 */
export function mkCorrelationId(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/**
 * Create an engine request.
 */
export function makeRequest(op: string, payload: unknown = {}): EngineRequest {
  return {
    op,
    v: CONTRACT_VERSION,
    payload,
    correlationId: mkCorrelationId(),
  };
}

/**
 * Create a successful response.
 */
export function ok<T = unknown>(result: T): EngineResponse {
  return { ok: true, result };
}

/**
 * Create an error response.
 */
export function err(code: string, message: string, details?: unknown): EngineResponse {
  const error: EngineErrorDetail = { code, message };
  if (details !== undefined) {
    error.details = details;
  }
  return { ok: false, error };
}

/**
 * Check if a response is successful.
 */
export function isOk(response: EngineResponse): response is EngineResponse & { ok: true; result: unknown } {
  return response.ok === true;
}

/**
 * Check if a response is an error.
 */
export function isErr(response: EngineResponse): response is EngineResponse & { ok: false; error: EngineErrorDetail } {
  return response.ok === false;
}

// =============================================================================
// INTENT TYPES
// =============================================================================

/**
 * Decision made on an intent.
 */
export type IntentDecision = 'ALLOW' | 'BLOCK' | 'ESCALATE';

/**
 * Status of an intent through the pipeline.
 */
export type IntentStatus =
  | 'received'
  | 'policy_resolved'
  | 'preflight_completed'
  | 'decided'
  | 'accepted'
  | 'denied'
  | 'escalated';

/**
 * Override AI provider/model for an intent.
 */
export interface AIOverride {
  provider?: string;
  model?: string;
}

/**
 * AI provider/model used for an intent.
 */
export interface AIUsed {
  provider: string;
  model: string;
}

/**
 * Request to submit an intent to the pipeline.
 */
export interface IntentRequest {
  op: string;
  payload: unknown;
  ai_override?: AIOverride;
}

/**
 * Result of submitting an intent.
 */
export interface IntentResult {
  intent_id: string;
  correlation_id: string;
  decision: IntentDecision;
  status: IntentStatus;
  ai_used?: AIUsed;
  reason?: string;
}

// =============================================================================
// POLICY TYPES
// =============================================================================

/**
 * What to do when no policy matches.
 */
export type FallbackBehavior = 'allow' | 'block' | 'escalate';

/**
 * Configuration for pre/post flight advisors.
 */
export interface FlightConfig {
  enabled: boolean;
  advisor_id: string;
}

/**
 * Default AI configuration.
 */
export interface AIDefaults {
  provider: string;
  model: string;
}

/**
 * Decision thresholds for advisors.
 */
export interface Thresholds {
  allow_min: number;
  escalate_below: number;
}

/**
 * A policy profile for an operation.
 */
export interface PolicyProfile {
  op: string;
  preflight: FlightConfig;
  postflight: FlightConfig;
  ai_defaults: AIDefaults;
  thresholds: Thresholds;
  allow_overrides: boolean;
  fallback: FallbackBehavior;
}

/**
 * Where a policy came from.
 */
export interface PolicySource {
  type: 'bundle' | 'default';
  bundle_id?: string;
  version?: string;
}

/**
 * A resolved policy with its source.
 */
export interface ResolvedPolicy {
  profile: PolicyProfile;
  source: PolicySource;
}

// =============================================================================
// VAULT TYPES
// =============================================================================

/**
 * Information about an installed bundle.
 */
export interface BundleInfo {
  bundle_id: string;
  version: string;
  installed_at: string;
}

/**
 * Bundle to install into the vault.
 */
export interface BundleInstall {
  id: string;
  version: string;
  policies: PolicyProfile[];
}

// =============================================================================
// PIPELINE EVENT TYPES
// =============================================================================

/**
 * Types of pipeline events.
 */
export type PipelineEventType =
  | 'intent_received'
  | 'policy_resolved'
  | 'preflight_completed'
  | 'intent_decided';

/**
 * An event emitted during pipeline processing.
 */
export interface PipelineEvent {
  type: PipelineEventType;
  intent_id: string;
  correlation_id: string;
  timestamp: string;
  // Event-specific fields
  op?: string;                    // intent_received
  policy_source?: PolicySource;   // policy_resolved
  advisor_id?: string;            // preflight_completed
  decision?: string;              // preflight_completed, intent_decided
  confidence?: number;            // preflight_completed
  reason?: string;                // intent_decided
}

// =============================================================================
// QUEUE EXTENDED TYPES
// =============================================================================

/**
 * Result of heartbeat operation.
 */
export interface HeartbeatResult {
  expires_at: string;
}
