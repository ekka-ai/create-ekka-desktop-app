/**
 * EKKA Pipeline API
 *
 * Intent pipeline operations.
 */

import type { EngineResponse, IntentRequest, IntentResult, PipelineEvent } from '../types';
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
// PIPELINE API
// =============================================================================

/**
 * Submit an intent to the pipeline for processing.
 * Returns the result of the intent decision.
 */
export async function submit(request: IntentRequest): Promise<IntentResult> {
  const req = makeRequest(OPS.PIPELINE_SUBMIT, request);
  const response = await getBackend().request(req);
  return processResponse<IntentResult>(response);
}

/**
 * Get the event history for an intent.
 * Returns all events emitted during pipeline processing.
 */
export async function events(intent_id: string): Promise<PipelineEvent[]> {
  const req = makeRequest(OPS.PIPELINE_EVENTS, { intent_id });
  const response = await getBackend().request(req);
  return processResponse<PipelineEvent[]>(response);
}

/**
 * Pipeline API namespace.
 */
export const pipeline = {
  submit,
  events,
};
