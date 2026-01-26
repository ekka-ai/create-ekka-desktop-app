/**
 * EKKA Demo Backend
 *
 * Fully functional in-memory implementation of the EKKA Backend interface.
 * No network calls. No persistence. Everything runs in the browser.
 * Perfect for learning and prototyping.
 */

import type {
  EngineRequest,
  EngineResponse,
  QueuedJob,
  Job,
  BundleInfo,
  BundleInstall,
  PolicyProfile,
  ResolvedPolicy,
  IntentRequest,
  IntentResult,
  IntentDecision,
  IntentStatus,
  PipelineEvent,
} from '../types';
import type { Backend } from './interface';
import { OPS, ERROR_CODES } from '../constants';
import { ok, err, mkCorrelationId } from '../types';

/**
 * Demo backend using in-memory storage.
 * Used when engine is not present.
 */
export class DemoBackend implements Backend {
  /** Connection state */
  private connected = false;

  /** Key-value store */
  private dbStore: Map<string, unknown> = new Map();

  /** Job queue */
  private jobQueue: QueuedJob[] = [];

  /** Simple incrementing ID for jobs */
  private nextJobId = 1;

  /** Vault initialization state */
  private vaultInitialized = false;

  /** Installed bundles */
  private bundles: Map<string, BundleInfo> = new Map();

  /** Policy registry (op -> policy) */
  private policies: Map<string, PolicyProfile> = new Map();

  /** Policy to bundle mapping */
  private policyBundleMap: Map<string, { bundle_id: string; version: string }> = new Map();

  /** Pipeline events by intent_id */
  private events: Map<string, PipelineEvent[]> = new Map();

  // ===========================================================================
  // BACKEND INTERFACE
  // ===========================================================================

  async connect(): Promise<void> {
    // Simulate async for API consistency
    await Promise.resolve();
    this.connected = true;
  }

  disconnect(): void {
    this.connected = false;
  }

  isConnected(): boolean {
    return this.connected;
  }

  async request(req: EngineRequest): Promise<EngineResponse> {
    // Simulate async for API consistency
    await Promise.resolve();
    return this.handle(req);
  }

  // ===========================================================================
  // REQUEST HANDLER
  // ===========================================================================

  /**
   * Handle an EngineRequest and return an EngineResponse.
   * Main entry point for the demo backend.
   */
  private handle(req: EngineRequest): EngineResponse {
    // Check connection for non-runtime ops
    if (req.op !== OPS.RUNTIME_INFO && !this.connected) {
      return err(ERROR_CODES.NOT_CONNECTED, 'Not connected. Call ekka.connect() first.');
    }

    switch (req.op) {
      // -----------------------------------------------------------------------
      // Runtime
      // -----------------------------------------------------------------------
      case OPS.RUNTIME_INFO: {
        return ok({
          runtime: 'demo',
          engine_present: false,
          mode: 'demo',
        });
      }

      // -----------------------------------------------------------------------
      // Database
      // -----------------------------------------------------------------------
      case OPS.DB_GET: {
        const payload = req.payload as { key: string };
        if (!payload || typeof payload.key !== 'string') {
          return err(ERROR_CODES.INVALID_PAYLOAD, 'Missing or invalid key');
        }
        return ok(this.dbGet(payload.key));
      }

      case OPS.DB_PUT: {
        const payload = req.payload as { key: string; value: unknown };
        if (!payload || typeof payload.key !== 'string') {
          return err(ERROR_CODES.INVALID_PAYLOAD, 'Missing or invalid key');
        }
        this.dbPut(payload.key, payload.value);
        return ok(null);
      }

      case OPS.DB_DELETE: {
        const payload = req.payload as { key: string };
        if (!payload || typeof payload.key !== 'string') {
          return err(ERROR_CODES.INVALID_PAYLOAD, 'Missing or invalid key');
        }
        this.dbDelete(payload.key);
        return ok(null);
      }

      // -----------------------------------------------------------------------
      // Queue
      // -----------------------------------------------------------------------
      case OPS.QUEUE_ENQUEUE: {
        const payload = req.payload as { kind: string; payload: unknown };
        if (!payload || typeof payload.kind !== 'string') {
          return err(ERROR_CODES.INVALID_PAYLOAD, 'Missing or invalid kind');
        }
        const jobId = this.queueEnqueue(payload.kind, payload.payload);
        return ok({ jobId });
      }

      case OPS.QUEUE_CLAIM: {
        return ok(this.queueClaim());
      }

      case OPS.QUEUE_ACK: {
        const payload = req.payload as { jobId: string };
        if (!payload || typeof payload.jobId !== 'string') {
          return err(ERROR_CODES.INVALID_PAYLOAD, 'Missing or invalid jobId');
        }
        this.queueAck(payload.jobId);
        return ok(null);
      }

      case OPS.QUEUE_NACK: {
        const payload = req.payload as { jobId: string };
        if (!payload || typeof payload.jobId !== 'string') {
          return err(ERROR_CODES.INVALID_PAYLOAD, 'Missing or invalid jobId');
        }
        this.queueNack(payload.jobId);
        return ok(null);
      }

      case OPS.QUEUE_HEARTBEAT: {
        const payload = req.payload as { jobId: string; leaseId: string };
        if (!payload || typeof payload.jobId !== 'string') {
          return err(ERROR_CODES.INVALID_PAYLOAD, 'Missing or invalid jobId');
        }
        return ok(this.queueHeartbeat(payload.jobId, payload.leaseId));
      }

      // -----------------------------------------------------------------------
      // Pipeline
      // -----------------------------------------------------------------------
      case OPS.PIPELINE_SUBMIT: {
        const payload = req.payload as IntentRequest;
        if (!payload || typeof payload.op !== 'string') {
          return err(ERROR_CODES.INVALID_PAYLOAD, 'Missing or invalid op');
        }
        return ok(this.pipelineSubmit(payload));
      }

      case OPS.PIPELINE_EVENTS: {
        const payload = req.payload as { intent_id: string };
        if (!payload || typeof payload.intent_id !== 'string') {
          return err(ERROR_CODES.INVALID_PAYLOAD, 'Missing or invalid intent_id');
        }
        return ok(this.pipelineEvents(payload.intent_id));
      }

      // -----------------------------------------------------------------------
      // Vault
      // -----------------------------------------------------------------------
      case OPS.VAULT_INIT: {
        this.vaultInit();
        return ok(null);
      }

      case OPS.VAULT_IS_INITIALIZED: {
        return ok({ initialized: this.vaultInitialized });
      }

      case OPS.VAULT_INSTALL: {
        const payload = req.payload as { bundle: BundleInstall };
        if (!payload || !payload.bundle || typeof payload.bundle.id !== 'string') {
          return err(ERROR_CODES.INVALID_PAYLOAD, 'Missing or invalid bundle');
        }
        return ok(this.vaultInstall(payload.bundle));
      }

      case OPS.VAULT_LIST_BUNDLES: {
        return ok(this.vaultListBundles());
      }

      case OPS.VAULT_SHOW_POLICY: {
        const payload = req.payload as { op: string };
        if (!payload || typeof payload.op !== 'string') {
          return err(ERROR_CODES.INVALID_PAYLOAD, 'Missing or invalid op');
        }
        return ok(this.vaultShowPolicy(payload.op));
      }

      // -----------------------------------------------------------------------
      // Unknown
      // -----------------------------------------------------------------------
      default:
        return err(ERROR_CODES.INVALID_OP, `Unknown operation: ${req.op}`);
    }
  }

  // ===========================================================================
  // DATABASE OPERATIONS (private)
  // ===========================================================================

  private dbGet<T = unknown>(key: string): T | null {
    const value = this.dbStore.get(key);
    return value !== undefined ? (value as T) : null;
  }

  private dbPut<T = unknown>(key: string, value: T): void {
    this.dbStore.set(key, value);
  }

  private dbDelete(key: string): void {
    this.dbStore.delete(key);
  }

  // ===========================================================================
  // QUEUE OPERATIONS (private)
  // ===========================================================================

  private queueEnqueue<T = unknown>(kind: string, payload: T): string {
    const id = `job-${this.nextJobId++}`;
    this.jobQueue.push({
      id,
      kind,
      payload,
      created_at: new Date().toISOString(),
      claimed: false,
    });
    return id;
  }

  private queueClaim<T = unknown>(): Job<T> | null {
    const job = this.jobQueue.find((j) => !j.claimed);
    if (!job) return null;
    job.claimed = true;
    return {
      id: job.id,
      kind: job.kind,
      payload: job.payload as T,
      created_at: job.created_at,
    };
  }

  private queueAck(jobId: string): void {
    const index = this.jobQueue.findIndex((j) => j.id === jobId);
    if (index !== -1) {
      this.jobQueue.splice(index, 1);
    }
  }

  private queueNack(jobId: string): void {
    const job = this.jobQueue.find((j) => j.id === jobId);
    if (job) {
      job.claimed = false;
    }
  }

  private queueHeartbeat(jobId: string, leaseId: string): { expires_at: string } {
    // In demo, just return extended time (no real lease tracking)
    // jobId and leaseId are intentionally unused in demo mode
    void jobId;
    void leaseId;
    const expires_at = new Date(Date.now() + 5 * 60 * 1000).toISOString();
    return { expires_at };
  }

  // ===========================================================================
  // PIPELINE OPERATIONS (private)
  // ===========================================================================

  private pipelineSubmit(request: IntentRequest): IntentResult {
    const intent_id = mkCorrelationId();
    const correlation_id = mkCorrelationId();

    // Emit intent_received event
    this.emitEvent(intent_id, {
      type: 'intent_received',
      intent_id,
      correlation_id,
      op: request.op,
      timestamp: new Date().toISOString(),
    });

    // Resolve policy (use default if not found)
    const resolved = this.vaultShowPolicy(request.op);
    const policy = resolved?.profile ?? this.defaultPolicy(request.op);

    this.emitEvent(intent_id, {
      type: 'policy_resolved',
      intent_id,
      correlation_id,
      policy_source: resolved?.source ?? { type: 'default' },
      timestamp: new Date().toISOString(),
    });

    // Stub advisor - always ALLOW for demo
    const decision: IntentDecision = 'ALLOW';
    const confidence = 1.0;

    this.emitEvent(intent_id, {
      type: 'preflight_completed',
      intent_id,
      correlation_id,
      advisor_id: 'stub.allow',
      decision,
      confidence,
      timestamp: new Date().toISOString(),
    });

    // Final decision
    const status: IntentStatus = 'accepted';

    this.emitEvent(intent_id, {
      type: 'intent_decided',
      intent_id,
      correlation_id,
      decision,
      timestamp: new Date().toISOString(),
    });

    return {
      intent_id,
      correlation_id,
      decision,
      status,
      ai_used: {
        provider: policy.ai_defaults.provider,
        model: policy.ai_defaults.model,
      },
    };
  }

  private pipelineEvents(intent_id: string): PipelineEvent[] {
    return this.events.get(intent_id) ?? [];
  }

  private emitEvent(intent_id: string, event: PipelineEvent): void {
    const list = this.events.get(intent_id) ?? [];
    list.push(event);
    this.events.set(intent_id, list);
  }

  // ===========================================================================
  // VAULT OPERATIONS (private)
  // ===========================================================================

  private vaultInit(): void {
    this.vaultInitialized = true;
  }

  private vaultInstall(bundle: BundleInstall): BundleInfo {
    const info: BundleInfo = {
      bundle_id: bundle.id,
      version: bundle.version,
      installed_at: new Date().toISOString(),
    };
    this.bundles.set(bundle.id, info);

    // Register policies from bundle
    for (const policy of bundle.policies) {
      this.policies.set(policy.op, policy);
      this.policyBundleMap.set(policy.op, { bundle_id: bundle.id, version: bundle.version });
    }

    return info;
  }

  private vaultListBundles(): BundleInfo[] {
    return Array.from(this.bundles.values());
  }

  private vaultShowPolicy(op: string): ResolvedPolicy | null {
    const policy = this.policies.get(op);
    if (!policy) return null;

    const bundleInfo = this.policyBundleMap.get(op);
    return {
      profile: policy,
      source: bundleInfo
        ? { type: 'bundle', bundle_id: bundleInfo.bundle_id, version: bundleInfo.version }
        : { type: 'default' },
    };
  }

  private defaultPolicy(op: string): PolicyProfile {
    return {
      op,
      preflight: { enabled: true, advisor_id: 'stub.allow' },
      postflight: { enabled: false, advisor_id: 'stub.allow' },
      ai_defaults: { provider: 'stub', model: 'stub-v1' },
      thresholds: { allow_min: 0.8, escalate_below: 0.5 },
      allow_overrides: true,
      fallback: 'escalate',
    };
  }

  // ===========================================================================
  // DEBUG / RESET (for testing)
  // ===========================================================================

  /**
   * Reset all state (for testing).
   */
  resetAll(): void {
    this.dbStore.clear();
    this.jobQueue.length = 0;
    this.nextJobId = 1;
    this.connected = false;
    this.vaultInitialized = false;
    this.bundles.clear();
    this.policies.clear();
    this.policyBundleMap.clear();
    this.events.clear();
  }
}

/**
 * Singleton instance of DemoBackend.
 */
export const demoBackend = new DemoBackend();
