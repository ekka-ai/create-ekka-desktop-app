/**
 * EKKA Queue API
 *
 * Job queue operations.
 */

import type { EngineResponse, Job, HeartbeatResult } from '../types';
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
// QUEUE API
// =============================================================================

/**
 * Enqueue a job into the job queue.
 */
export async function enqueue<T = unknown>(kind: string, payload: T): Promise<string> {
  const req = makeRequest(OPS.QUEUE_ENQUEUE, { kind, payload });
  const response = await getBackend().request(req);
  const result = processResponse<{ jobId: string }>(response);
  return result.jobId;
}

/**
 * Claim the next available job from the queue.
 * Returns null if no jobs are available.
 */
export async function claim<T = unknown>(): Promise<Job<T> | null> {
  const req = makeRequest(OPS.QUEUE_CLAIM, {});
  const response = await getBackend().request(req);
  return processResponse<Job<T> | null>(response);
}

/**
 * Acknowledge a job as completed.
 */
export async function ack(job: Job): Promise<void> {
  const req = makeRequest(OPS.QUEUE_ACK, { jobId: job.id });
  const response = await getBackend().request(req);
  processResponse<null>(response);
}

/**
 * Reject a job (return it to the queue).
 */
export async function nack(job: Job): Promise<void> {
  const req = makeRequest(OPS.QUEUE_NACK, { jobId: job.id });
  const response = await getBackend().request(req);
  processResponse<null>(response);
}

/**
 * Send a heartbeat to extend the lease on a claimed job.
 * Returns the new expiration time.
 */
export async function heartbeat(jobId: string, leaseId: string): Promise<HeartbeatResult> {
  const req = makeRequest(OPS.QUEUE_HEARTBEAT, { jobId, leaseId });
  const response = await getBackend().request(req);
  return processResponse<HeartbeatResult>(response);
}

/**
 * Queue API namespace.
 */
export const queue = {
  enqueue,
  claim,
  ack,
  nack,
  heartbeat,
};
