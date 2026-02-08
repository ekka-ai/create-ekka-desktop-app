/**
 * EKKA Demo App
 *
 * Flow:
 * 1. Check setup status (pre-login) - only node credentials
 * 2. If setup incomplete (no node credentials), show SetupWizard
 * 3. Connect to engine
 * 4. Check auth - if not logged in, show LoginPage
 * 5. After login, check home.status for HOME grant
 * 6. If not HOME_GRANTED, show HomeSetupPage (requests grant from engine)
 * 7. Show main app when HOME_GRANTED
 */

import { useState, useEffect, type ReactElement, type CSSProperties } from 'react';
import { ekka, advanced, EkkaError, addAuditEvent, type HomeStatus, type SetupStatus } from '../ekka';
import { Shell } from './layout/Shell';
import { type Page } from './layout/Sidebar';
import { SystemPage } from './pages/SystemPage';
import { AuditLogPage } from './pages/AuditLogPage';
import { PathPermissionsPage } from './pages/PathPermissionsPage';
import { VaultPage } from './pages/VaultPage';
import { RunnerPage } from './pages/RunnerPage';
import { ExecutionPlansPage } from './pages/ExecutionPlansPage';
import { ExecutionRunDetailPage } from './pages/ExecutionRunDetailPage';
import { LoginPage } from './pages/LoginPage';
import { HomeSetupPage } from './pages/HomeSetupPage';
import { SetupWizard } from './components/SetupWizard';

type AppState = 'loading' | 'setup' | 'login' | 'home-setup' | 'ready';

interface DemoState {
  appState: AppState;
  setupStatus: SetupStatus | null;
  homeStatus: HomeStatus | null;
  connected: boolean;
  error: string | null;
}

export function DemoApp(): ReactElement {
  const [selectedPage, setSelectedPage] = useState<Page>('path-permissions');
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [darkMode, setDarkMode] = useState<boolean>(() => {
    if (typeof window !== 'undefined') {
      return window.matchMedia('(prefers-color-scheme: dark)').matches;
    }
    return false;
  });
  const [state, setState] = useState<DemoState>({
    appState: 'loading',
    setupStatus: null,
    homeStatus: null,
    connected: false,
    error: null,
  });

  useEffect(() => {
    void initializeApp();
  }, []);

  async function initializeApp(): Promise<void> {
    try {
      // Step 1: Check setup status BEFORE connect (pre-login)
      const setupStatus = await ekka.setup.status();
      setState((s) => ({ ...s, setupStatus }));

      // Log setup gate status
      console.log(`[ekka] op=desktop.setup.gate setupComplete=${setupStatus.setupComplete}`);

      // HARD GATE: If setup is incomplete, show wizard - NO exceptions
      if (!setupStatus.setupComplete) {
        setState((s) => ({ ...s, appState: 'setup' }));
        return;
      }

      // Step 2: Connect to engine (REQUIRED before login)
      await ekka.connect();
      setState((s) => ({ ...s, connected: true }));

      console.log('[ekka] op=desktop.connect.success');

      addAuditEvent({
        type: 'connection.established',
        description: 'Connected to EKKA backend',
        technical: { mode: advanced.internal.mode() },
      });

      // Step 3: Check auth
      if (!ekka.auth.isLoggedIn()) {
        setState((s) => ({ ...s, appState: 'login' }));
        return;
      }

      const user = ekka.auth.user();
      if (user) {
        const tenantId = user.company?.id || 'default';
        await advanced.auth.setContext({ tenantId, sub: user.id, jwt: '' });
      }

      await checkHomeStatus();
    } catch (err: unknown) {
      const message = err instanceof EkkaError ? err.message : 'Connection failed';

      // Check if setup is incomplete - if so, stay in setup mode
      try {
        const setupStatus = await ekka.setup.status();
        if (!setupStatus.setupComplete) {
          setState((s) => ({ ...s, setupStatus, appState: 'setup', error: message }));
          return;
        }
      } catch {
        // If we can't check setup status, stay in loading with error
        setState((s) => ({ ...s, error: message }));
        return;
      }

      // Only go to login if setup IS complete but connection failed
      setState((s) => ({ ...s, error: message, appState: 'login' }));

      addAuditEvent({
        type: 'connection.failed',
        description: 'Failed to connect to EKKA backend',
        technical: { error: message },
      });
    }
  }

  async function checkHomeStatus(): Promise<void> {
    try {
      const status = await advanced.home.status();
      setState((s) => ({ ...s, homeStatus: status }));

      if (status.state === 'HOME_GRANTED') {
        setState((s) => ({ ...s, appState: 'ready' }));
      } else if (status.state === 'AUTHENTICATED_NO_HOME_GRANT') {
        setState((s) => ({ ...s, appState: 'home-setup' }));
      } else {
        setState((s) => ({ ...s, appState: 'login' }));
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to check home status';
      setState((s) => ({ ...s, error: message }));
    }
  }

  async function handleSetupComplete(): Promise<void> {
    // After setup wizard completes:
    // Wizard already verified credentials saved - proceed directly to login
    // (Don't re-verify via setup.status - keychain read-after-write has race condition)
    setState((s) => ({ ...s, appState: 'loading' }));

    try {
      // Ensure connected (wizard should have called connect, but verify)
      if (!ekka.isConnected()) {
        await ekka.connect();
        console.log('[ekka] op=desktop.connect.success (post-setup)');
      }
      setState((s) => ({ ...s, connected: true }));

      // Now proceed to login
      if (!ekka.auth.isLoggedIn()) {
        setState((s) => ({ ...s, appState: 'login' }));
        return;
      }

      // Already logged in - check home status
      await checkHomeStatus();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Setup verification failed';
      setState((s) => ({ ...s, error: message, appState: 'setup' }));
    }
  }

  async function handleLoginSuccess(): Promise<void> {
    // Belt + suspenders: ensure connected before any engine ops
    if (!state.connected) {
      try {
        await ekka.connect();
        setState((s) => ({ ...s, connected: true }));
        console.log('[ekka] op=desktop.connect.success (post-login)');
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Failed to connect';
        setState((s) => ({ ...s, error: message }));
        return;
      }
    }
    await checkHomeStatus();
  }

  function handleHomeGranted(): void {
    setState((s) => ({ ...s, appState: 'ready' }));
  }

  // Loading
  if (state.appState === 'loading') {
    const style: CSSProperties = {
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      minHeight: '100vh',
      background: darkMode ? '#1c1c1e' : '#ffffff',
      fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Text", system-ui, sans-serif',
      color: darkMode ? '#98989d' : '#86868b',
      fontSize: '14px',
    };
    return <div style={style}>Connecting...</div>;
  }

  // Setup wizard (pre-login)
  if (state.appState === 'setup' && state.setupStatus) {
    return (
      <SetupWizard
        initialStatus={state.setupStatus}
        onComplete={handleSetupComplete}
        darkMode={darkMode}
      />
    );
  }

  // Login
  if (state.appState === 'login') {
    return <LoginPage onLoginSuccess={handleLoginSuccess} darkMode={darkMode} />;
  }

  // Home setup
  if (state.appState === 'home-setup' && state.homeStatus) {
    return (
      <HomeSetupPage
        homeStatus={state.homeStatus}
        onGranted={handleHomeGranted}
        darkMode={darkMode}
      />
    );
  }

  // Main app
  const errorStyle: CSSProperties = {
    marginBottom: '20px',
    padding: '12px 14px',
    background: darkMode ? '#3c1618' : '#fef2f2',
    border: `1px solid ${darkMode ? '#7f1d1d' : '#fecaca'}`,
    borderRadius: '6px',
    fontSize: '13px',
    color: darkMode ? '#fca5a5' : '#991b1b',
  };

  return (
    <Shell
      selectedPage={selectedPage}
      onNavigate={setSelectedPage}
      darkMode={darkMode}
      onToggleDarkMode={() => setDarkMode((prev) => !prev)}
    >
      {state.error && <div style={errorStyle}>{state.error}</div>}
      {selectedPage === 'path-permissions' && <PathPermissionsPage darkMode={darkMode} />}
      {selectedPage === 'vault' && <VaultPage darkMode={darkMode} />}
      {selectedPage === 'runner' && <RunnerPage darkMode={darkMode} />}
      {selectedPage === 'execution-plans' && (
        selectedRunId
          ? <ExecutionRunDetailPage runId={selectedRunId} onBack={() => setSelectedRunId(null)} darkMode={darkMode} />
          : <ExecutionPlansPage darkMode={darkMode} onViewRun={(id) => setSelectedRunId(id)} />
      )}
      {selectedPage === 'audit-log' && <AuditLogPage darkMode={darkMode} />}
      {selectedPage === 'system' && <SystemPage darkMode={darkMode} />}
    </Shell>
  );
}
