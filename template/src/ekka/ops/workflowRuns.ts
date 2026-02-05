/**
 * Workflow Runs Operations (DEPRECATED - V1/Temporal)
 *
 * @deprecated Use executionRuns.ts instead. V1 workflow runs use Temporal which is no longer active.
 * This module is preserved for backwards compatibility only. New code should use V2 execution runs.
 *
 * Create and poll workflow runs via Rust proxy.
 * All HTTP is handled by Rust - no fetch() in TS.
 */

import { OPS } from '../constants';
import { _internal, makeRequest } from '../internal';
import { getAccessToken } from '../auth/storage';

// =============================================================================
// TYPES
// =============================================================================

export interface WorkflowRunCreateRequest {
  type: string;
  confidentiality: 'public' | 'confidential';
  context: {
    prompt_ref: {
      provider: string;
      prompt_slug: string;
      prompt_version: string;
    };
    variables: Record<string, string>;
  };
}

export interface WorkflowRunCreateResponse {
  id: string;
  status: string;
}

/** Debug bundle info (only present for REPORT_INVALID in dev mode) */
export interface DebugBundleInfo {
  /** Vault URI (e.g., "vault://tmp/telemetry/llm_debug/{tenant}/{run_id}/") */
  debug_bundle_ref: string;
  /** SHA256 hash of raw output */
  raw_output_sha256: string;
  /** Length of raw output in bytes */
  raw_output_len: number;
  /** Files in the bundle */
  files: string[];
}

export interface WorkflowRunResult {
  output_text?: string;
  /** Debug bundle info (only present for REPORT_INVALID failures in dev mode) */
  debug_bundle?: DebugBundleInfo;
  [key: string]: unknown;
}

export interface WorkflowRun {
  id: string;
  type?: string;
  workflow_definition_id?: string;
  status: 'pending' | 'dispatched' | 'running' | 'completed' | 'failed' | 'cancelled';
  progress: number;
  result?: WorkflowRunResult;
  error?: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
}

// =============================================================================
// OPERATIONS
// =============================================================================

/**
 * Create a new workflow run.
 *
 * @param request - Workflow run creation request
 * @returns Created workflow run with ID
 */
export async function createWorkflowRun(
  request: WorkflowRunCreateRequest
): Promise<WorkflowRunCreateResponse> {
  const jwt = getAccessToken();

  const req = makeRequest(OPS.WORKFLOW_RUNS_CREATE, {
    request,
    jwt,
  });

  const response = await _internal.request(req);

  if (!response.ok) {
    throw new Error(response.error?.message || 'Failed to create workflow run');
  }

  return response.result as WorkflowRunCreateResponse;
}

/**
 * Get workflow run status and output.
 *
 * @param id - Workflow run ID
 * @returns Workflow run details
 */
export async function getWorkflowRun(id: string): Promise<WorkflowRun> {
  const jwt = getAccessToken();

  const req = makeRequest(OPS.WORKFLOW_RUNS_GET, {
    id,
    jwt,
  });

  const response = await _internal.request(req);

  if (!response.ok) {
    throw new Error(response.error?.message || 'Failed to get workflow run');
  }

  return response.result as WorkflowRun;
}
