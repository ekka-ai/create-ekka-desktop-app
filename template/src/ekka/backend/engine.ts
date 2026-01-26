/**
 * EKKA Engine Backend
 *
 * Backend implementation for Tauri IPC communication with the EKKA engine.
 * Forwards all requests to the Rust engine via Tauri invoke.
 */

import type { EngineRequest, EngineResponse } from '../types';
import type { Backend } from './interface';
import { ERROR_CODES } from '../constants';
import { err } from '../types';

/**
 * Engine backend using Tauri IPC.
 * Used when engine is present - forwards requests to EKKA engine.
 */
export class EngineBackend implements Backend {
  /** Connection state */
  private connected = false;

  // ===========================================================================
  // BACKEND INTERFACE
  // ===========================================================================

  async connect(): Promise<void> {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('engine_connect');
      this.connected = true;
    } catch (e) {
      const message = e instanceof Error ? e.message : 'Unknown connection error';
      throw new Error(`Failed to connect to engine: ${message}`);
    }
  }

  disconnect(): void {
    this.connected = false;
    // Note: Engine disconnect is fire-and-forget
    import('@tauri-apps/api/core')
      .then(({ invoke }) => invoke('engine_disconnect'))
      .catch(() => {
        // Ignore errors on disconnect
      });
  }

  isConnected(): boolean {
    return this.connected;
  }

  async request(req: EngineRequest): Promise<EngineResponse> {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const response = await invoke<EngineResponse>('engine_request', { req });
      return response;
    } catch (e) {
      const message = e instanceof Error ? e.message : 'Unknown invoke error';
      return err(ERROR_CODES.INTERNAL_ERROR, message);
    }
  }
}

/**
 * Singleton instance of EngineBackend.
 */
export const engineBackend = new EngineBackend();
