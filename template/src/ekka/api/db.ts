/**
 * EKKA Database API
 *
 * Key-value database operations.
 */

import type { EngineResponse } from '../types';
import { makeRequest } from '../types';
import { OPS } from '../constants';
import { getBackend } from '../core/runtime';
import { EkkaNotConnectedError, EkkaApiError } from '../errors';

// =============================================================================
// RESPONSE PROCESSOR
// =============================================================================

function processResponse<T>(response: EngineResponse): T {
  if (!response.ok) {
    const error = response.error;
    if (error?.code === 'NOT_CONNECTED') {
      throw new EkkaNotConnectedError();
    }
    throw new EkkaApiError(error?.message || 'Unknown error', error?.code || 'UNKNOWN');
  }
  return response.result as T;
}

// =============================================================================
// DATABASE API
// =============================================================================

/**
 * Get a value from the key-value store.
 */
export async function get<T = unknown>(key: string): Promise<T | null> {
  const req = makeRequest(OPS.DB_GET, { key });
  const response = await getBackend().request(req);
  return processResponse<T | null>(response);
}

/**
 * Put a value into the key-value store.
 */
export async function put<T = unknown>(key: string, value: T): Promise<void> {
  const req = makeRequest(OPS.DB_PUT, { key, value });
  const response = await getBackend().request(req);
  processResponse<null>(response);
}

/**
 * Delete a value from the key-value store.
 */
export async function del(key: string): Promise<void> {
  const req = makeRequest(OPS.DB_DELETE, { key });
  const response = await getBackend().request(req);
  processResponse<null>(response);
}

/**
 * Database API namespace.
 */
export const db = {
  get,
  put,
  delete: del,
};
