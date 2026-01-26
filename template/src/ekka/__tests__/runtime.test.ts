/**
 * Runtime Selection Unit Tests
 * Tests that backend selection works correctly based on engine presence.
 */

import { describe, test, expect } from 'vitest';
import { selectBackend } from '../core/runtime';
import { DemoBackend, EngineBackend } from '../backend';
import type { RuntimeInfo } from '../types';

describe('selectBackend()', () => {
  test('selects DemoBackend when engine_present=false (web)', () => {
    const info: RuntimeInfo = {
      runtime: 'web',
      engine_present: false,
    };

    const { backend, mode } = selectBackend(info);

    expect(backend).toBeInstanceOf(DemoBackend);
    expect(mode).toBe('demo');
  });

  test('selects DemoBackend when runtime=tauri but engine_present=false (stub build)', () => {
    const info: RuntimeInfo = {
      runtime: 'tauri',
      engine_present: false,
    };

    const { backend, mode } = selectBackend(info);

    expect(backend).toBeInstanceOf(DemoBackend);
    expect(mode).toBe('demo');
  });

  test('selects EngineBackend when engine_present=true (production build)', () => {
    const info: RuntimeInfo = {
      runtime: 'tauri',
      engine_present: true,
    };

    const { backend, mode } = selectBackend(info);

    expect(backend).toBeInstanceOf(EngineBackend);
    expect(mode).toBe('engine');
  });
});
