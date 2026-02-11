/**
 * EKKA Internal Backend
 *
 * Connects to EKKA Bridge (engine mode only).
 * This module is NOT exported publicly - only accessible via _internal.
 */

import type { EngineRequest, EngineResponse } from '../types';
import { err, makeRequest } from '../types';

/**
 * Transport mode - always 'engine' after successful connect.
 */
export type TransportMode = 'unknown' | 'engine';

/**
 * Backend init error with detailed failure context.
 */
export interface BackendInitError {
  op: string;
  error_message: string;
  stack?: string;
  ts_timestamp: string;
  correlation_id: string;
}

/**
 * EngineBackend - connects to EKKA Bridge only.
 * Hard-fails if engine_connect fails (no demo fallback).
 */
class EngineBackend {
  private mode: TransportMode = 'unknown';
  private connected = false;

  /**
   * Connect to EKKA Bridge.
   * Throws BackendInitError on failure.
   */
  async connect(): Promise<void> {
    if (this.connected) return;

    const correlationId = crypto.randomUUID();

    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('engine_connect');
      this.mode = 'engine';
      this.connected = true;

      console.log(`[desktop.backend.init.success] correlation_id=${correlationId} mode=engine`);
      return;
    } catch (e: unknown) {
      const error_message = e instanceof Error ? e.message : String(e);
      const stack = e instanceof Error ? e.stack : undefined;

      const initError: BackendInitError = {
        op: 'engine_connect',
        error_message,
        stack,
        ts_timestamp: new Date().toISOString(),
        correlation_id: correlationId,
      };

      // Log structured failure
      console.error(
        `[desktop.backend.init.failed] correlation_id=${correlationId} op=engine_connect error="${error_message}"`,
        { details: initError }
      );

      // Re-throw as Error with serialized details
      const fatalError = new Error(`Engine connection failed: ${error_message}`) as Error & {
        backendInitError: BackendInitError;
      };
      fatalError.backendInitError = initError;
      throw fatalError;
    }
  }

  /**
   * Disconnect from the backend.
   */
  disconnect(): void {
    if (!this.connected) return;

    // Fire and forget
    import('@tauri-apps/api/core')
      .then(({ invoke }) => invoke('engine_disconnect'))
      .catch(() => {});

    this.connected = false;
    this.mode = 'unknown';
  }

  /**
   * Check if connected.
   */
  isConnected(): boolean {
    return this.connected;
  }

  /**
   * Get current transport mode.
   */
  getMode(): TransportMode {
    return this.mode;
  }

  /**
   * Send a request to the backend.
   */
  async request(req: EngineRequest): Promise<EngineResponse> {
    // LOCAL-ONLY OPERATIONS: Always route to Bridge, regardless of connection state
    // These are desktop-specific operations that must be handled by Rust handlers
    const localOnlyOps = [
      'setup.status',
      'nodeCredentials.set',
      'nodeCredentials.status',
      'nodeCredentials.clear',
    ];

    const isLocalOnlyOp = localOnlyOps.includes(req.op);

    if (isLocalOnlyOp) {
      console.log(`[ts.op.dispatch] op=${req.op} backend=bridge (local-only)`);
      try {
        const { invoke } = await import('@tauri-apps/api/core');
        return await invoke<EngineResponse>('engine_request', { req });
      } catch (e) {
        const message = e instanceof Error ? e.message : 'Bridge not available';
        console.error(`[ts.op.dispatch] op=${req.op} backend=bridge FAILED: ${message}`);
        return err('BRIDGE_NOT_READY', message);
      }
    }

    if (!this.connected) {
      return err('NOT_CONNECTED', 'Not connected. Call ekka.connect() first.');
    }

    console.log(`[ts.op.dispatch] op=${req.op} backend=${this.mode} connected=${this.connected}`);

    // All ops go to engine (demo mode removed)
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      return await invoke<EngineResponse>('engine_request', { req });
    } catch (e) {
      const message = e instanceof Error ? e.message : 'Unknown invoke error';
      return err('INTERNAL_ERROR', message);
    }
  }
}

// =============================================================================
// INTERNAL API (not exported from package)
// =============================================================================

const backend = new EngineBackend();

/**
 * Internal API - only accessible within the ekka package.
 * NOT exported from the main index.ts.
 */
export const _internal = {
  connect: () => backend.connect(),
  disconnect: () => backend.disconnect(),
  isConnected: () => backend.isConnected(),
  getMode: () => backend.getMode(),
  request: (req: EngineRequest) => backend.request(req),
};

// Re-export makeRequest for use by index.ts
export { makeRequest };
