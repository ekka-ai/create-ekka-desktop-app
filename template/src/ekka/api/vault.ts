/**
 * EKKA Vault API
 *
 * Policy vault operations.
 */

import type { EngineResponse, BundleInfo, BundleInstall, ResolvedPolicy } from '../types';
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
// VAULT API
// =============================================================================

/**
 * Initialize the vault.
 */
export async function init(): Promise<void> {
  const req = makeRequest(OPS.VAULT_INIT, {});
  const response = await getBackend().request(req);
  processResponse<null>(response);
}

/**
 * Check if the vault is initialized.
 */
export async function isInitialized(): Promise<boolean> {
  const req = makeRequest(OPS.VAULT_IS_INITIALIZED, {});
  const response = await getBackend().request(req);
  return processResponse<{ initialized: boolean }>(response).initialized;
}

/**
 * Install a policy bundle into the vault.
 */
export async function install(bundle: BundleInstall): Promise<BundleInfo> {
  const req = makeRequest(OPS.VAULT_INSTALL, { bundle });
  const response = await getBackend().request(req);
  return processResponse<BundleInfo>(response);
}

/**
 * List all installed bundles.
 */
export async function listBundles(): Promise<BundleInfo[]> {
  const req = makeRequest(OPS.VAULT_LIST_BUNDLES, {});
  const response = await getBackend().request(req);
  return processResponse<BundleInfo[]>(response);
}

/**
 * Show the resolved policy for an operation.
 * Returns null if no policy is registered for the operation.
 */
export async function showPolicy(op: string): Promise<ResolvedPolicy | null> {
  const req = makeRequest(OPS.VAULT_SHOW_POLICY, { op });
  const response = await getBackend().request(req);
  return processResponse<ResolvedPolicy | null>(response);
}

/**
 * Vault API namespace.
 */
export const vault = {
  init,
  isInitialized,
  install,
  listBundles,
  showPolicy,
};
