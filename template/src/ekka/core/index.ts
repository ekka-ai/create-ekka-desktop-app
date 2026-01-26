/**
 * EKKA Core Module
 *
 * Internal runtime machinery for the EKKA client.
 */

// Runtime management
export {
  detectRuntime,
  getRuntimeInfo,
  selectBackend,
  initRuntime,
  isInitialized,
  getCurrentRuntimeInfo,
  getBackend,
  getCurrentMode,
  refreshRuntimeInfo,
} from './runtime';
