/**
 * Demo Backend Unit Tests
 * Tests the DemoBackend class implementing the Backend interface.
 */

import { describe, test, expect, beforeEach } from 'vitest';
import { DemoBackend } from '../backend/demo';
import { mkCorrelationId } from '../types';
import { OPS } from '../constants';

function makeRequest(op: string, payload: unknown = {}) {
  return {
    op,
    v: 1,
    payload,
    correlationId: mkCorrelationId(),
  };
}

describe('DemoBackend', () => {
  let backend: DemoBackend;

  beforeEach(() => {
    backend = new DemoBackend();
  });

  describe('connection management', () => {
    test('starts disconnected', () => {
      expect(backend.isConnected()).toBe(false);
    });

    test('connect() sets connected state', async () => {
      await backend.connect();
      expect(backend.isConnected()).toBe(true);
    });

    test('disconnect() clears connected state', async () => {
      await backend.connect();
      backend.disconnect();
      expect(backend.isConnected()).toBe(false);
    });
  });

  describe('request() with connection', () => {
    beforeEach(async () => {
      await backend.connect();
    });

    test('db.put/db.get roundtrip', async () => {
      // Put
      const putResp = await backend.request(makeRequest(OPS.DB_PUT, { key: 'test-key', value: 'test-value' }));
      expect(putResp.ok).toBe(true);
      expect(putResp.result).toBeNull();

      // Get
      const getResp = await backend.request(makeRequest(OPS.DB_GET, { key: 'test-key' }));
      expect(getResp.ok).toBe(true);
      expect(getResp.result).toBe('test-value');
    });

    test('db.get returns null for missing key', async () => {
      const resp = await backend.request(makeRequest(OPS.DB_GET, { key: 'nonexistent' }));
      expect(resp.ok).toBe(true);
      expect(resp.result).toBeNull();
    });

    test('queue.enqueue/claim/ack roundtrip', async () => {
      // Enqueue
      const enqResp = await backend.request(makeRequest(OPS.QUEUE_ENQUEUE, { kind: 'test-job', payload: { data: 123 } }));
      expect(enqResp.ok).toBe(true);
      expect(enqResp.result).toHaveProperty('jobId');

      // Claim
      const claimResp = await backend.request(makeRequest(OPS.QUEUE_CLAIM, {}));
      expect(claimResp.ok).toBe(true);
      expect(claimResp.result).toHaveProperty('id');
      expect(claimResp.result).toHaveProperty('kind', 'test-job');
      expect(claimResp.result).toHaveProperty('payload', { data: 123 });

      const job = claimResp.result as { id: string };

      // Ack
      const ackResp = await backend.request(makeRequest(OPS.QUEUE_ACK, { jobId: job.id }));
      expect(ackResp.ok).toBe(true);

      // Claim again - should be empty
      const claim2Resp = await backend.request(makeRequest(OPS.QUEUE_CLAIM, {}));
      expect(claim2Resp.ok).toBe(true);
      expect(claim2Resp.result).toBeNull();
    });

    test('returns INVALID_OP for unknown operation', async () => {
      const resp = await backend.request(makeRequest('unknown.op', {}));
      expect(resp.ok).toBe(false);
      expect(resp.error?.code).toBe('INVALID_OP');
    });
  });

  describe('request() without connection', () => {
    test('returns NOT_CONNECTED when not connected', async () => {
      const resp = await backend.request(makeRequest(OPS.DB_GET, { key: 'test' }));
      expect(resp.ok).toBe(false);
      expect(resp.error?.code).toBe('NOT_CONNECTED');
    });

    test('runtime.info works without connection', async () => {
      const resp = await backend.request(makeRequest(OPS.RUNTIME_INFO, {}));
      expect(resp.ok).toBe(true);
      expect(resp.result).toHaveProperty('runtime', 'demo');
      expect(resp.result).toHaveProperty('engine_present', false);
    });
  });

  describe('resetAll()', () => {
    test('resets all state', async () => {
      await backend.connect();
      await backend.request(makeRequest(OPS.DB_PUT, { key: 'test', value: 'value' }));

      backend.resetAll();

      expect(backend.isConnected()).toBe(false);
      // After reset, need to connect again to access data
      await backend.connect();
      const resp = await backend.request(makeRequest(OPS.DB_GET, { key: 'test' }));
      expect(resp.result).toBeNull();
    });
  });

  describe('queue.heartbeat', () => {
    beforeEach(async () => {
      await backend.connect();
    });

    test('returns extended expiration time', async () => {
      const resp = await backend.request(
        makeRequest(OPS.QUEUE_HEARTBEAT, { jobId: 'job-1', leaseId: 'lease-1' })
      );
      expect(resp.ok).toBe(true);
      expect(resp.result).toHaveProperty('expires_at');
      const result = resp.result as { expires_at: string };
      expect(new Date(result.expires_at).getTime()).toBeGreaterThan(Date.now());
    });
  });

  describe('pipeline operations', () => {
    beforeEach(async () => {
      await backend.connect();
    });

    test('pipeline.submit returns IntentResult', async () => {
      const resp = await backend.request(
        makeRequest(OPS.PIPELINE_SUBMIT, { op: 'test.echo', payload: { msg: 'hello' } })
      );
      expect(resp.ok).toBe(true);
      const result = resp.result as {
        intent_id: string;
        correlation_id: string;
        decision: string;
        status: string;
      };
      expect(result).toHaveProperty('intent_id');
      expect(result).toHaveProperty('correlation_id');
      expect(result).toHaveProperty('decision', 'ALLOW');
      expect(result).toHaveProperty('status', 'accepted');
      expect(result).toHaveProperty('ai_used');
    });

    test('pipeline.events returns event history', async () => {
      // Submit an intent first
      const submitResp = await backend.request(
        makeRequest(OPS.PIPELINE_SUBMIT, { op: 'test.op', payload: {} })
      );
      expect(submitResp.ok).toBe(true);
      const { intent_id } = submitResp.result as { intent_id: string };

      // Get events
      const eventsResp = await backend.request(
        makeRequest(OPS.PIPELINE_EVENTS, { intent_id })
      );
      expect(eventsResp.ok).toBe(true);
      const events = eventsResp.result as Array<{ type: string }>;
      expect(events).toHaveLength(4);
      expect(events[0].type).toBe('intent_received');
      expect(events[1].type).toBe('policy_resolved');
      expect(events[2].type).toBe('preflight_completed');
      expect(events[3].type).toBe('intent_decided');
    });

    test('pipeline.events returns empty array for unknown intent', async () => {
      const resp = await backend.request(
        makeRequest(OPS.PIPELINE_EVENTS, { intent_id: 'unknown-id' })
      );
      expect(resp.ok).toBe(true);
      expect(resp.result).toEqual([]);
    });
  });

  describe('vault operations', () => {
    beforeEach(async () => {
      await backend.connect();
    });

    test('vault.init/isInitialized flow', async () => {
      // Initially not initialized
      const checkResp1 = await backend.request(makeRequest(OPS.VAULT_IS_INITIALIZED, {}));
      expect(checkResp1.ok).toBe(true);
      expect((checkResp1.result as { initialized: boolean }).initialized).toBe(false);

      // Initialize
      const initResp = await backend.request(makeRequest(OPS.VAULT_INIT, {}));
      expect(initResp.ok).toBe(true);

      // Now initialized
      const checkResp2 = await backend.request(makeRequest(OPS.VAULT_IS_INITIALIZED, {}));
      expect(checkResp2.ok).toBe(true);
      expect((checkResp2.result as { initialized: boolean }).initialized).toBe(true);
    });

    test('vault.install creates bundle', async () => {
      const bundle = {
        id: 'test-bundle',
        version: '1.0.0',
        policies: [
          {
            op: 'test.op',
            preflight: { enabled: true, advisor_id: 'advisor-1' },
            postflight: { enabled: false, advisor_id: 'advisor-1' },
            ai_defaults: { provider: 'openai', model: 'gpt-4' },
            thresholds: { allow_min: 0.8, escalate_below: 0.5 },
            allow_overrides: true,
            fallback: 'escalate' as const,
          },
        ],
      };

      const resp = await backend.request(makeRequest(OPS.VAULT_INSTALL, { bundle }));
      expect(resp.ok).toBe(true);
      const result = resp.result as { bundle_id: string; version: string; installed_at: string };
      expect(result.bundle_id).toBe('test-bundle');
      expect(result.version).toBe('1.0.0');
      expect(result.installed_at).toBeDefined();
    });

    test('vault.listBundles returns installed bundles', async () => {
      // Initially empty
      const listResp1 = await backend.request(makeRequest(OPS.VAULT_LIST_BUNDLES, {}));
      expect(listResp1.ok).toBe(true);
      expect(listResp1.result).toEqual([]);

      // Install a bundle
      const bundle = {
        id: 'my-bundle',
        version: '2.0.0',
        policies: [],
      };
      await backend.request(makeRequest(OPS.VAULT_INSTALL, { bundle }));

      // Now list shows the bundle
      const listResp2 = await backend.request(makeRequest(OPS.VAULT_LIST_BUNDLES, {}));
      expect(listResp2.ok).toBe(true);
      const bundles = listResp2.result as Array<{ bundle_id: string }>;
      expect(bundles).toHaveLength(1);
      expect(bundles[0].bundle_id).toBe('my-bundle');
    });

    test('vault.showPolicy returns policy or null', async () => {
      // No policy initially
      const showResp1 = await backend.request(
        makeRequest(OPS.VAULT_SHOW_POLICY, { op: 'unknown.op' })
      );
      expect(showResp1.ok).toBe(true);
      expect(showResp1.result).toBeNull();

      // Install bundle with policy
      const bundle = {
        id: 'policy-bundle',
        version: '1.0.0',
        policies: [
          {
            op: 'defined.op',
            preflight: { enabled: true, advisor_id: 'adv' },
            postflight: { enabled: false, advisor_id: 'adv' },
            ai_defaults: { provider: 'anthropic', model: 'claude-3' },
            thresholds: { allow_min: 0.9, escalate_below: 0.3 },
            allow_overrides: false,
            fallback: 'block' as const,
          },
        ],
      };
      await backend.request(makeRequest(OPS.VAULT_INSTALL, { bundle }));

      // Now policy is found
      const showResp2 = await backend.request(
        makeRequest(OPS.VAULT_SHOW_POLICY, { op: 'defined.op' })
      );
      expect(showResp2.ok).toBe(true);
      const resolved = showResp2.result as {
        profile: { op: string };
        source: { type: string; bundle_id: string };
      };
      expect(resolved.profile.op).toBe('defined.op');
      expect(resolved.source.type).toBe('bundle');
      expect(resolved.source.bundle_id).toBe('policy-bundle');
    });
  });
});
