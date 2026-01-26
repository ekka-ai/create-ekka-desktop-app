/**
 * EKKA Backend Interface
 *
 * Defines the contract for all backend implementations.
 * Both DemoBackend and EngineBackend implement this interface.
 */

import type { EngineRequest, EngineResponse } from '../types';

/**
 * Backend interface for EKKA operations.
 * All requests flow through a backend implementing this interface.
 */
export interface Backend {
  /**
   * Connect to the backend.
   * Must be called before any db/queue operations.
   */
  connect(): Promise<void>;

  /**
   * Disconnect from the backend.
   */
  disconnect(): void;

  /**
   * Check if connected to the backend.
   */
  isConnected(): boolean;

  /**
   * Send a request to the backend and receive a response.
   * Single RPC method for all operations.
   */
  request(req: EngineRequest): Promise<EngineResponse>;
}
