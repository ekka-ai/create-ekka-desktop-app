/**
 * EKKA Demo Backend
 *
 * In-memory implementation for development/testing.
 * Only implements ops that have real Rust implementations.
 */

import type { EngineRequest, EngineResponse } from '../types';
import type { Backend } from './interface';
import { OPS, ERROR_CODES } from '../constants';
import { ok, err } from '../types';
import branding from '../../../branding/app.json';

// Derive display-only home path from branding (no OS detection, works in browser)
function slugify(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
}
const DEMO_HOME_PATH = `~/.local/share/${slugify(branding.name) || 'ekka-desktop'}`;

/**
 * Demo backend using in-memory storage.
 * Used when Tauri engine is not available.
 */
export class DemoBackend implements Backend {
  private connected = false;
  private authContext: { tenantId: string; sub: string; jwt: string } | null = null;
  private homeGranted = false;

  async connect(): Promise<void> {
    await Promise.resolve();
    this.connected = true;
  }

  disconnect(): void {
    this.connected = false;
    this.authContext = null;
    this.homeGranted = false;
  }

  isConnected(): boolean {
    return this.connected;
  }

  async request(req: EngineRequest): Promise<EngineResponse> {
    await Promise.resolve();
    return this.handle(req);
  }

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
          homeState: this.getHomeState(),
          homePath: DEMO_HOME_PATH,
        });
      }

      // -----------------------------------------------------------------------
      // Auth
      // -----------------------------------------------------------------------
      case OPS.AUTH_SET: {
        const payload = req.payload as { tenantId?: string; sub?: string; jwt?: string };

        if (!payload?.tenantId || !payload?.sub || !payload?.jwt) {
          return err(ERROR_CODES.INVALID_PAYLOAD, 'Missing tenantId, sub, or jwt');
        }

        this.authContext = {
          tenantId: payload.tenantId,
          sub: payload.sub,
          jwt: payload.jwt,
        };

        return ok({ ok: true });
      }

      // -----------------------------------------------------------------------
      // Home
      // -----------------------------------------------------------------------
      case OPS.HOME_STATUS: {
        return ok({
          state: this.getHomeState(),
          homePath: DEMO_HOME_PATH,
          grantPresent: this.homeGranted,
          reason: this.homeGranted ? null : 'Demo mode - call home.grant to simulate',
        });
      }

      case OPS.HOME_GRANT: {
        if (!this.authContext) {
          return err(ERROR_CODES.NOT_AUTHENTICATED, 'Must call auth.set before home.grant');
        }

        // Simulate grant issuance
        this.homeGranted = true;

        return ok({
          success: true,
          grant_id: 'demo-grant-' + Date.now(),
          expires_at: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
        });
      }

      // -----------------------------------------------------------------------
      // Unknown
      // -----------------------------------------------------------------------
      default:
        return err(ERROR_CODES.INVALID_OP, `Unknown operation: ${req.op}`);
    }
  }

  private getHomeState(): string {
    if (this.homeGranted) return 'HOME_GRANTED';
    if (this.authContext) return 'AUTHENTICATED_NO_HOME_GRANT';
    return 'BOOTSTRAP_PRE_LOGIN';
  }

  /**
   * Reset all state (for testing).
   */
  resetAll(): void {
    this.connected = false;
    this.authContext = null;
    this.homeGranted = false;
  }
}

export const demoBackend = new DemoBackend();
