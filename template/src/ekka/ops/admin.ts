/**
 * Admin Operations
 *
 * Admin log fetching proxied via Desktop Core → engine API.
 */

import { OPS } from '../constants';
import { _internal, makeRequest } from '../internal';

// =============================================================================
// TYPES
// =============================================================================

export interface AdminLogEntry {
  ts: string;
  level: string;
  component: string;
  op?: string;
  path?: string;
  status?: number | string;
  message?: string;
  fields?: Record<string, unknown>;
}

export interface AdminLogsResult {
  correlation_id: string;
  total: number;
  logs: AdminLogEntry[];
}

export interface AdminLogsOptions {
  since?: string;
  limit?: number;
  service?: string;
}

// =============================================================================
// OPERATIONS
// =============================================================================

/**
 * Fetch correlated admin logs from engine.
 *
 * Proxied through Desktop Core to avoid CORS and handle auth.
 */
export async function logs(
  correlationId: string,
  opts?: AdminLogsOptions,
): Promise<AdminLogsResult> {
  const req = makeRequest(OPS.ADMIN_LOGS, {
    correlation_id: correlationId,
    since: opts?.since,
    limit: opts?.limit,
    service: opts?.service,
  });
  const response = await _internal.request(req);

  if (!response.ok) {
    throw new Error(response.error?.message || 'Failed to fetch admin logs');
  }

  return response.result as AdminLogsResult;
}
