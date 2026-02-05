/**
 * Runner Operations
 *
 * Local runner status for this desktop instance.
 * Task queue stats from engine API (proxied via Rust).
 */

import { OPS } from '../constants';
import { _internal, makeRequest } from '../internal';

// =============================================================================
// TYPES
// =============================================================================

export type RunnerLoopState = 'running' | 'stopped' | 'error';

export interface RunnerStatus {
  enabled: boolean;
  state: RunnerLoopState;
  runnerId: string | null;
  engineUrl: string | null;
  lastPollAt: string | null;
  lastClaimAt: string | null;
  lastCompleteAt: string | null;
  lastTaskId: string | null;
  lastError: string | null;
}

/** Task queue stats from engine API (V2) */
export interface RunnerTaskStats {
  counts: {
    pending: number;
    claimed: number;
    completed_5m: number;
    failed_5m: number;
  };
  /** V2: by_capability (was by_subtype in v1) */
  by_capability: Record<string, { pending: number; claimed: number }>;
  /** @deprecated Use by_capability instead - aliased for backwards compat */
  by_subtype?: Record<string, { pending: number; claimed: number }>;
  recent: Array<{
    task_id: string;
    /** V2: capability_identity (was task_subtype in v1) */
    capability_identity: string;
    /** @deprecated Use capability_identity instead */
    task_subtype?: string | null;
    status: string;
    /** V2: claimed_by (was runner_id in v1) */
    claimed_by: string | null;
    /** @deprecated Use claimed_by instead */
    runner_id?: string | null;
    created_at: string;
    claimed_at: string | null;
    /** V2: deadline_at (was lease_expires_at in v1) */
    deadline_at: string | null;
    /** @deprecated Use deadline_at instead */
    lease_expires_at?: string | null;
  }>;
  active_runners: Array<{
    runner_id: string;
    last_claimed_at: string;
  }>;
  /** Warning banner to display in UI */
  warning: string | null;
}

// =============================================================================
// OPERATIONS
// =============================================================================

/**
 * Get local runner status for this desktop instance.
 */
export async function status(): Promise<RunnerStatus> {
  const req = makeRequest('runner.status', {});
  const response = await _internal.request(req);

  if (!response.ok) {
    throw new Error(response.error?.message || 'Failed to get runner status');
  }

  return response.result as RunnerStatus;
}

/**
 * Get runner task queue stats from engine API.
 *
 * Proxied through Rust backend to avoid CORS.
 * Requires node authentication (setup must be complete).
 */
export async function taskStats(): Promise<RunnerTaskStats> {
  const req = makeRequest(OPS.RUNNER_TASK_STATS, {});
  const response = await _internal.request(req);

  if (!response.ok) {
    throw new Error(response.error?.message || 'Failed to fetch runner task stats');
  }

  return response.result as RunnerTaskStats;
}
