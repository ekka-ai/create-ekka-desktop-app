/**
 * EKKA Constants
 *
 * Central constants for operation names and error codes.
 * These define the contract between client and engine.
 */

// =============================================================================
// OPERATION NAMES
// =============================================================================

/**
 * All supported RPC operation names.
 */
export const OPS = {
  // Runtime
  RUNTIME_INFO: 'runtime.info',

  // Database
  DB_GET: 'db.get',
  DB_PUT: 'db.put',
  DB_DELETE: 'db.delete',

  // Queue
  QUEUE_ENQUEUE: 'queue.enqueue',
  QUEUE_CLAIM: 'queue.claim',
  QUEUE_ACK: 'queue.ack',
  QUEUE_NACK: 'queue.nack',
  QUEUE_HEARTBEAT: 'queue.heartbeat',

  // Pipeline
  PIPELINE_SUBMIT: 'pipeline.submit',
  PIPELINE_EVENTS: 'pipeline.events',

  // Vault
  VAULT_INIT: 'vault.init',
  VAULT_IS_INITIALIZED: 'vault.isInitialized',
  VAULT_INSTALL: 'vault.install',
  VAULT_LIST_BUNDLES: 'vault.listBundles',
  VAULT_SHOW_POLICY: 'vault.showPolicy',
} as const;

/**
 * Operation name type.
 */
export type OpName = (typeof OPS)[keyof typeof OPS];

// =============================================================================
// ERROR CODES
// =============================================================================

/**
 * Standard error codes returned by the engine.
 */
export const ERROR_CODES = {
  NOT_CONNECTED: 'NOT_CONNECTED',
  ENGINE_NOT_PRESENT: 'ENGINE_NOT_PRESENT',
  NOT_IMPLEMENTED: 'NOT_IMPLEMENTED',
  INVALID_OP: 'INVALID_OP',
  INVALID_PAYLOAD: 'INVALID_PAYLOAD',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
} as const;

/**
 * Error code type.
 */
export type ErrorCode = (typeof ERROR_CODES)[keyof typeof ERROR_CODES];

// =============================================================================
// CONTRACT VERSION
// =============================================================================

/**
 * Current contract version.
 */
export const CONTRACT_VERSION = 1;
