/**
 * EKKA Constants
 *
 * Operation names and error codes.
 * Only includes IMPLEMENTED operations.
 */

// =============================================================================
// OPERATION NAMES (only implemented ops)
// =============================================================================

export const OPS = {
  // Setup
  SETUP_STATUS: 'setup.status',

  // Runtime
  RUNTIME_INFO: 'runtime.info',

  // Auth
  AUTH_SET: 'auth.set',

  // Node Session
  NODE_SESSION_ENSURE_IDENTITY: 'nodeSession.ensureIdentity',
  NODE_SESSION_BOOTSTRAP: 'nodeSession.bootstrap',
  NODE_SESSION_STATUS: 'nodeSession.status',

  // Node Credentials (keychain-stored)
  NODE_CREDENTIALS_SET: 'nodeCredentials.set',
  NODE_CREDENTIALS_STATUS: 'nodeCredentials.status',
  NODE_CREDENTIALS_CLEAR: 'nodeCredentials.clear',

  // Runner
  RUNNER_STATUS: 'runner.status',
  RUNNER_TASK_STATS: 'runner.taskStats',

  // Auth (proxied via Rust)
  AUTH_LOGIN: 'auth.login',
  AUTH_REFRESH: 'auth.refresh',
  AUTH_LOGOUT: 'auth.logout',

  // Home
  HOME_STATUS: 'home.status',
  HOME_GRANT: 'home.grant',

  // Paths
  PATHS_CHECK: 'paths.check',
  PATHS_LIST: 'paths.list',
  PATHS_GET: 'paths.get',
  PATHS_REQUEST: 'paths.request',
  PATHS_REMOVE: 'paths.remove',

  // Vault - Status/Capabilities
  VAULT_STATUS: 'vault.status',
  VAULT_CAPABILITIES: 'vault.capabilities',

  // Vault - Secrets
  VAULT_SECRETS_LIST: 'vault.secrets.list',
  VAULT_SECRETS_GET: 'vault.secrets.get',
  VAULT_SECRETS_CREATE: 'vault.secrets.create',
  VAULT_SECRETS_UPDATE: 'vault.secrets.update',
  VAULT_SECRETS_DELETE: 'vault.secrets.delete',
  VAULT_SECRETS_UPSERT: 'vault.secrets.upsert',

  // Vault - Bundles
  VAULT_BUNDLES_LIST: 'vault.bundles.list',
  VAULT_BUNDLES_GET: 'vault.bundles.get',
  VAULT_BUNDLES_CREATE: 'vault.bundles.create',
  VAULT_BUNDLES_RENAME: 'vault.bundles.rename',
  VAULT_BUNDLES_DELETE: 'vault.bundles.delete',
  VAULT_BUNDLES_LIST_SECRETS: 'vault.bundles.listSecrets',
  VAULT_BUNDLES_ADD_SECRET: 'vault.bundles.addSecret',
  VAULT_BUNDLES_REMOVE_SECRET: 'vault.bundles.removeSecret',

  // Vault - Files
  VAULT_FILES_WRITE_TEXT: 'vault.files.writeText',
  VAULT_FILES_WRITE_BYTES: 'vault.files.writeBytes',
  VAULT_FILES_READ_TEXT: 'vault.files.readText',
  VAULT_FILES_READ_BYTES: 'vault.files.readBytes',
  VAULT_FILES_LIST: 'vault.files.list',
  VAULT_FILES_EXISTS: 'vault.files.exists',
  VAULT_FILES_DELETE: 'vault.files.delete',
  VAULT_FILES_MKDIR: 'vault.files.mkdir',
  VAULT_FILES_MOVE: 'vault.files.move',

  // Vault - Injection (DEFERRED - returns NOT_IMPLEMENTED)
  VAULT_ATTACH_SECRETS_TO_CONNECTOR: 'vault.attachSecretsToConnector',
  VAULT_INJECT_SECRETS_INTO_RUN: 'vault.injectSecretsIntoRun',

  // Vault - Audit
  VAULT_AUDIT_LIST: 'vault.audit.list',

  // Admin
  ADMIN_LOGS: 'admin.logs',
} as const;

export type OpName = (typeof OPS)[keyof typeof OPS];

// =============================================================================
// ERROR CODES
// =============================================================================

export const ERROR_CODES = {
  NOT_CONNECTED: 'NOT_CONNECTED',
  NOT_AUTHENTICATED: 'NOT_AUTHENTICATED',
  HOME_GRANT_REQUIRED: 'HOME_GRANT_REQUIRED',
  INVALID_OP: 'INVALID_OP',
  INVALID_PAYLOAD: 'INVALID_PAYLOAD',
  INTERNAL_ERROR: 'INTERNAL_ERROR',

  // Vault
  VAULT_NOT_INITIALIZED: 'VAULT_NOT_INITIALIZED',
  VAULT_ERROR: 'VAULT_ERROR',
  SECRET_NOT_FOUND: 'SECRET_NOT_FOUND',
  SECRET_ALREADY_EXISTS: 'SECRET_ALREADY_EXISTS',
  BUNDLE_NOT_FOUND: 'BUNDLE_NOT_FOUND',
  BUNDLE_ALREADY_EXISTS: 'BUNDLE_ALREADY_EXISTS',

  // Files
  FILE_NOT_FOUND: 'FILE_NOT_FOUND',
  FILE_ALREADY_EXISTS: 'FILE_ALREADY_EXISTS',
  DIRECTORY_NOT_EMPTY: 'DIRECTORY_NOT_EMPTY',
  INVALID_PATH: 'INVALID_PATH',
  PATH_TRAVERSAL_DENIED: 'PATH_TRAVERSAL_DENIED',

  // Deferred
  NOT_IMPLEMENTED: 'NOT_IMPLEMENTED',

  // Credentials
  INVALID_NODE_ID: 'INVALID_NODE_ID',
  INVALID_NODE_SECRET: 'INVALID_NODE_SECRET',
  CREDENTIALS_STORE_ERROR: 'CREDENTIALS_STORE_ERROR',
  CREDENTIALS_CLEAR_ERROR: 'CREDENTIALS_CLEAR_ERROR',
  CREDENTIALS_NOT_CONFIGURED: 'CREDENTIALS_NOT_CONFIGURED',
} as const;

export type ErrorCode = (typeof ERROR_CODES)[keyof typeof ERROR_CODES];

// =============================================================================
// CONTRACT VERSION
// =============================================================================

export const CONTRACT_VERSION = 2;
