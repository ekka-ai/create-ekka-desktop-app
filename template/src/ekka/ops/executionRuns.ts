/**
 * Execution Runs Operations
 *
 * Start execution plan runs via the V2 run-start API.
 * MVP: Uses direct HTTP fetch with stored JWT token.
 *
 * This bypasses the Rust proxy for simplicity in the MVP.
 * Future: Route through engine_request like other ops.
 */

import { getAccessToken } from '../auth/storage';
import { ENGINE_BASE_URL } from '../config';

// =============================================================================
// TYPES
// =============================================================================

export interface ExecutionRunStartRequest {
  plan_id: string;
  inputs: Record<string, unknown>;
}

export interface ExecutionRunStartResponse {
  run_id: string;
  task_id: string;
  correlation_id: string;
  status: string;
}

export interface ExecutionRun {
  id: string;
  plan_id: string;
  plan_identity: string;
  status: 'pending' | 'running' | 'paused' | 'completed' | 'failed' | 'cancelled' | 'timeout';
  current_step_index: number;
  total_steps: number;
  completed_steps: number;
  progress: number;
  context?: Record<string, unknown>;
  result?: Record<string, unknown>;
  error?: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  duration_ms?: number;
}

// =============================================================================
// CONFIG
// =============================================================================

// MVP plan ID for DocGen Basic (V2)
export const DOCGEN_BASIC_PLAN_ID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890';

// =============================================================================
// HTTP HELPERS
// =============================================================================

function getSecurityHeaders(): Record<string, string> {
  const requestId = crypto.randomUUID();
  return {
    'Content-Type': 'application/json',
    'X-REQUEST-ID': requestId,
    'X-EKKA-CORRELATION-ID': requestId,
    'X-EKKA-MODULE': 'studio.docgen',
    'X-EKKA-ACTION': 'run.start',
    'X-EKKA-CLIENT': 'ekka-desktop-app',
    'X-EKKA-CLIENT-VERSION': '1.0.0',
    'X-EKKA-PROOF-TYPE': 'jwt',
  };
}

// =============================================================================
// OPERATIONS
// =============================================================================

/**
 * Start a new execution plan run.
 *
 * @param request - Plan ID and inputs
 * @returns Created run with run_id
 */
export async function startExecutionRun(
  request: ExecutionRunStartRequest
): Promise<ExecutionRunStartResponse> {
  const jwt = getAccessToken();
  if (!jwt) {
    throw new Error('Not authenticated. Please login first.');
  }

  const headers: Record<string, string> = {
    ...getSecurityHeaders(),
    'Authorization': `Bearer ${jwt}`,
  };

  const response = await fetch(`${ENGINE_BASE_URL}/engine/execution/runs`, {
    method: 'POST',
    headers,
    body: JSON.stringify(request),
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    const message = (errorBody as { message?: string }).message || `HTTP ${response.status}`;
    throw new Error(`Failed to start execution run: ${message}`);
  }

  return response.json() as Promise<ExecutionRunStartResponse>;
}

/**
 * Get execution run status.
 *
 * @param runId - Execution run ID
 * @returns Execution run details
 */
export async function getExecutionRun(runId: string): Promise<ExecutionRun> {
  const jwt = getAccessToken();
  if (!jwt) {
    throw new Error('Not authenticated. Please login first.');
  }

  const headers: Record<string, string> = {
    ...getSecurityHeaders(),
    'Authorization': `Bearer ${jwt}`,
  };

  const response = await fetch(`${ENGINE_BASE_URL}/engine/admin/execution/runs/${runId}`, {
    method: 'GET',
    headers,
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    const message = (errorBody as { message?: string }).message || `HTTP ${response.status}`;
    throw new Error(`Failed to get execution run: ${message}`);
  }

  const data = await response.json() as { run: ExecutionRun };

  // Map to expected format with computed progress
  const run = data.run;
  return {
    ...run,
    progress: run.total_steps > 0 ? Math.round((run.completed_steps / run.total_steps) * 100) : 0,
  };
}
