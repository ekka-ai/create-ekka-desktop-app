/**
 * EKKA Runtime Manager
 *
 * Handles runtime detection and backend selection.
 * Auto-selects demo or engine mode based on environment.
 */

import type { RuntimeInfo, RuntimeType, TransportMode } from '../types';
import type { Backend } from '../backend/interface';
import { demoBackend, engineBackend } from '../backend';

// =============================================================================
// STATE
// =============================================================================

let currentRuntimeInfo: RuntimeInfo = {
  runtime: 'web',
  engine_present: false,
};

let currentBackend: Backend = demoBackend;
let currentMode: TransportMode = 'demo';
let initialized = false;

// =============================================================================
// DETECTION
// =============================================================================

/**
 * Detect if running in Tauri or web environment.
 */
export function detectRuntime(): RuntimeType {
  if (typeof window !== 'undefined' && '__TAURI__' in window) {
    return 'tauri';
  }
  return 'web';
}

/**
 * Get runtime info from Tauri or return web defaults.
 */
export async function getRuntimeInfo(): Promise<RuntimeInfo> {
  const runtime = detectRuntime();

  if (runtime === 'web') {
    return {
      runtime: 'web',
      engine_present: false,
    };
  }

  // In Tauri, check if engine is embedded (production) or stub (dev)
  try {
    const { invoke } = await import('@tauri-apps/api/core');
    const info = await invoke<{
      runtime: string;
      engine_present: boolean;
    }>('get_runtime_info');

    return {
      runtime: 'tauri',
      engine_present: info.engine_present,
    };
  } catch {
    // Stub build or invoke failed - use DemoBackend
    return {
      runtime: 'tauri',
      engine_present: false,
    };
  }
}

// =============================================================================
// BACKEND SELECTION
// =============================================================================

/**
 * Select backend based on runtime info.
 */
export function selectBackend(info: RuntimeInfo): { backend: Backend; mode: TransportMode } {
  if (info.engine_present) {
    return { backend: engineBackend, mode: 'engine' };
  }
  return { backend: demoBackend, mode: 'demo' };
}

// =============================================================================
// INITIALIZATION
// =============================================================================

/**
 * Initialize runtime - detect environment and select backend.
 * Must be called once at app startup.
 */
export async function initRuntime(): Promise<void> {
  if (initialized) {
    return;
  }

  currentRuntimeInfo = await getRuntimeInfo();
  const { backend, mode } = selectBackend(currentRuntimeInfo);
  currentBackend = backend;
  currentMode = mode;
  initialized = true;
}

/**
 * Check if runtime has been initialized.
 */
export function isInitialized(): boolean {
  return initialized;
}

// =============================================================================
// ACCESSORS
// =============================================================================

/**
 * Get current runtime info.
 */
export function getCurrentRuntimeInfo(): RuntimeInfo {
  return currentRuntimeInfo;
}

/**
 * Get current backend.
 */
export function getBackend(): Backend {
  return currentBackend;
}

/**
 * Get current mode.
 */
export function getCurrentMode(): TransportMode {
  return currentMode;
}

/**
 * Refresh runtime info (e.g., when Settings page loads).
 */
export async function refreshRuntimeInfo(): Promise<RuntimeInfo> {
  currentRuntimeInfo = await getRuntimeInfo();
  const { backend, mode } = selectBackend(currentRuntimeInfo);
  currentBackend = backend;
  currentMode = mode;
  return currentRuntimeInfo;
}
