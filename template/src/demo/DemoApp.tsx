/**
 * EKKA Demo App
 * Professional admin-style UI with left navigation and dark mode
 */

import { useState, useEffect, type ReactElement } from 'react';
import { ekka, EkkaError } from '../ekka';
import { Shell } from './layout/Shell';
import { Page } from './layout/Sidebar';
import { StatefulData } from './pages/StatefulData';
import { AsyncWork } from './pages/AsyncWork';
import { SettingsPage } from './pages/SettingsPage';

interface DemoState {
  connected: boolean;
  connecting: boolean;
  error: string | null;
  dbValue: string | null;
  queueJobId: string | null;
}

export function DemoApp(): ReactElement {
  const [selectedPage, setSelectedPage] = useState<Page>('stateful-data');
  const [darkMode, setDarkMode] = useState<boolean>(() => {
    if (typeof window !== 'undefined') {
      return window.matchMedia('(prefers-color-scheme: dark)').matches;
    }
    return false;
  });
  const [state, setState] = useState<DemoState>({
    connected: false,
    connecting: false,
    error: null,
    dbValue: null,
    queueJobId: null,
  });

  const [inputKey, setInputKey] = useState('demo-key');
  const [inputValue, setInputValue] = useState('Hello EKKA!');
  const [queueKind, setQueueKind] = useState('demo-job');
  const [queuePayload, setQueuePayload] = useState('{"message": "Hello from queue"}');

  useEffect(() => {
    void handleConnect();
  }, []);

  async function handleConnect(): Promise<void> {
    setState((s) => ({ ...s, connecting: true, error: null }));
    try {
      await ekka.init();
      await ekka.connect();
      setState((s) => ({ ...s, connected: true, connecting: false }));
    } catch (err: unknown) {
      const message = err instanceof EkkaError ? err.message : 'Unknown error';
      setState((s) => ({ ...s, connecting: false, error: message }));
    }
  }

  function handleError(error: string | null): void {
    setState((s) => ({ ...s, error }));
  }

  function handleDbValueChange(value: string | null): void {
    setState((s) => ({ ...s, dbValue: value }));
  }

  function handleJobIdChange(jobId: string | null): void {
    setState((s) => ({ ...s, queueJobId: jobId }));
  }

  function toggleDarkMode(): void {
    setDarkMode((prev) => !prev);
  }

  const errorStyle: React.CSSProperties = {
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
      onToggleDarkMode={toggleDarkMode}
    >
      {state.error && <div style={errorStyle}>{state.error}</div>}

      {selectedPage === 'stateful-data' && (
        <StatefulData
          connected={state.connected}
          inputKey={inputKey}
          inputValue={inputValue}
          dbValue={state.dbValue}
          onKeyChange={setInputKey}
          onValueChange={setInputValue}
          onDbValueChange={handleDbValueChange}
          onError={handleError}
          darkMode={darkMode}
        />
      )}

      {selectedPage === 'async-work' && (
        <AsyncWork
          connected={state.connected}
          queueKind={queueKind}
          queuePayload={queuePayload}
          queueJobId={state.queueJobId}
          onKindChange={setQueueKind}
          onPayloadChange={setQueuePayload}
          onJobIdChange={handleJobIdChange}
          onError={handleError}
          darkMode={darkMode}
        />
      )}

      {selectedPage === 'settings' && <SettingsPage darkMode={darkMode} />}
    </Shell>
  );
}
