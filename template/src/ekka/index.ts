/**
 * EKKA Client
 *
 * Main entry point for the EKKA client library.
 *
 * @example
 * ```typescript
 * import { ekka } from './ekka';
 *
 * await ekka.init();
 * await ekka.connect();
 * await ekka.db.put('key', value);
 * const data = await ekka.db.get('key');
 * ```
 */

import {
  initRuntime,
  getBackend,
  getCurrentRuntimeInfo,
  getCurrentMode,
  refreshRuntimeInfo,
} from './core/runtime';
import { db } from './api/db';
import { queue } from './api/queue';
import { pipeline } from './api/pipeline';
import { vault } from './api/vault';

// =============================================================================
// PUBLIC API
// =============================================================================

/**
 * EKKA client instance.
 * This is the main entry point for all EKKA operations.
 */
export const ekka = {
  /**
   * Initialize the EKKA runtime.
   * Auto-detects environment and selects appropriate backend.
   * Call once at app startup.
   */
  init: initRuntime,

  /**
   * Connect to the EKKA environment.
   * Must be called before any db/queue operations.
   */
  connect: () => getBackend().connect(),

  /**
   * Disconnect from the EKKA environment.
   */
  disconnect: () => getBackend().disconnect(),

  /**
   * Check if connected.
   */
  isConnected: () => getBackend().isConnected(),

  /**
   * Runtime information and mode.
   */
  runtime: {
    /** Get current runtime info. */
    info: getCurrentRuntimeInfo,
    /** Get current transport mode ('demo' or 'engine'). */
    mode: getCurrentMode,
    /** Refresh runtime info (re-detect environment). */
    refresh: refreshRuntimeInfo,
  },

  /**
   * Key-value database operations.
   */
  db,

  /**
   * Job queue operations.
   */
  queue,

  /**
   * Intent pipeline operations.
   */
  pipeline,

  /**
   * Policy vault operations.
   */
  vault,
};

// =============================================================================
// TYPE EXPORTS
// =============================================================================

export type {
  // Contract types
  EngineRequest,
  EngineResponse,
  EngineErrorDetail,
  // Runtime types
  RuntimeType,
  TransportMode,
  RuntimeInfo,
  // API types
  Job,
  SessionInfo,
  // Intent types
  IntentDecision,
  IntentStatus,
  AIOverride,
  AIUsed,
  IntentRequest,
  IntentResult,
  // Policy types
  FallbackBehavior,
  FlightConfig,
  AIDefaults,
  Thresholds,
  PolicyProfile,
  PolicySource,
  ResolvedPolicy,
  // Vault types
  BundleInfo,
  BundleInstall,
  // Pipeline event types
  PipelineEventType,
  PipelineEvent,
  // Queue extended types
  HeartbeatResult,
} from './types';

// =============================================================================
// ERROR EXPORTS
// =============================================================================

export {
  EkkaError,
  EkkaNotConnectedError,
  EkkaConnectionError,
  EkkaApiError,
  EkkaEngineNotPresentError,
} from './errors';

// =============================================================================
// CONSTANT EXPORTS
// =============================================================================

export { OPS, ERROR_CODES, CONTRACT_VERSION } from './constants';
export type { OpName, ErrorCode } from './constants';
