/**
 * Stateful Data Page
 * Database operations demo with dark mode support
 */

import { type CSSProperties, type ReactElement } from 'react';
import { ekka, EkkaError } from '../../ekka';

interface StatefulDataProps {
  connected: boolean;
  inputKey: string;
  inputValue: string;
  dbValue: string | null;
  onKeyChange: (key: string) => void;
  onValueChange: (value: string) => void;
  onDbValueChange: (value: string | null) => void;
  onError: (error: string | null) => void;
  darkMode: boolean;
}

export function StatefulData({
  connected,
  inputKey,
  inputValue,
  dbValue,
  onKeyChange,
  onValueChange,
  onDbValueChange,
  onError,
  darkMode,
}: StatefulDataProps): ReactElement {
  async function handleDbPut(): Promise<void> {
    try {
      await ekka.db.put(inputKey, inputValue);
      onError(null);
    } catch (err: unknown) {
      const message = err instanceof EkkaError ? err.message : 'Unknown error';
      onError(message);
    }
  }

  async function handleDbGet(): Promise<void> {
    try {
      const value = await ekka.db.get<string>(inputKey);
      onDbValueChange(value);
      onError(null);
    } catch (err: unknown) {
      const message = err instanceof EkkaError ? err.message : 'Unknown error';
      onError(message);
    }
  }

  const colors = {
    text: darkMode ? '#ffffff' : '#1d1d1f',
    textMuted: darkMode ? '#98989d' : '#6e6e73',
    bg: darkMode ? '#2c2c2e' : '#fafafa',
    border: darkMode ? '#3a3a3c' : '#e5e5e5',
    inputBg: darkMode ? '#1c1c1e' : '#ffffff',
    inputBorder: darkMode ? '#3a3a3c' : '#d2d2d7',
    buttonBg: darkMode ? '#0a84ff' : '#1d1d1f',
    buttonDisabled: darkMode ? '#48484a' : '#86868b',
    resultBg: darkMode ? '#1c3a5e' : '#f0f5ff',
    resultBorder: darkMode ? '#2563eb' : '#d4e0ff',
    codeBg: darkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.04)',
  };

  const styles: Record<string, CSSProperties> = {
    header: { marginBottom: '24px' },
    title: {
      fontSize: '20px',
      fontWeight: 600,
      color: colors.text,
      marginBottom: '8px',
      letterSpacing: '-0.01em',
    },
    description: {
      fontSize: '13px',
      lineHeight: 1.5,
      color: colors.textMuted,
    },
    card: {
      background: colors.bg,
      border: `1px solid ${colors.border}`,
      borderRadius: '8px',
      padding: '20px',
    },
    formGroup: { marginBottom: '16px' },
    label: {
      display: 'block',
      fontSize: '12px',
      fontWeight: 500,
      color: colors.text,
      marginBottom: '6px',
    },
    input: {
      width: '100%',
      maxWidth: '320px',
      padding: '8px 12px',
      fontSize: '13px',
      border: `1px solid ${colors.inputBorder}`,
      borderRadius: '6px',
      background: colors.inputBg,
      color: colors.text,
      outline: 'none',
    },
    buttonGroup: { display: 'flex', gap: '8px', marginTop: '20px' },
    button: {
      padding: '8px 16px',
      fontSize: '13px',
      fontWeight: 500,
      color: '#ffffff',
      background: colors.buttonBg,
      border: 'none',
      borderRadius: '6px',
      cursor: 'pointer',
    },
    buttonDisabled: {
      background: colors.buttonDisabled,
      cursor: 'not-allowed',
    },
    result: {
      marginTop: '16px',
      padding: '12px 14px',
      background: colors.resultBg,
      border: `1px solid ${colors.resultBorder}`,
      borderRadius: '6px',
      fontSize: '13px',
      color: colors.text,
    },
    code: {
      fontFamily: 'SF Mono, Monaco, Consolas, monospace',
      fontSize: '12px',
      background: colors.codeBg,
      padding: '2px 6px',
      borderRadius: '4px',
    },
  };

  return (
    <div>
      <header style={styles.header}>
        <h1 style={styles.title}>Stateful Data</h1>
        <p style={styles.description}>
          Persist and retrieve information using EKKA's key-value store.
        </p>
      </header>

      <div style={styles.card}>
        <div style={styles.formGroup}>
          <label style={styles.label}>Key</label>
          <input
            type="text"
            value={inputKey}
            onChange={(e) => onKeyChange(e.target.value)}
            style={styles.input}
            placeholder="Enter a key"
          />
        </div>

        <div style={styles.formGroup}>
          <label style={styles.label}>Value</label>
          <input
            type="text"
            value={inputValue}
            onChange={(e) => onValueChange(e.target.value)}
            style={styles.input}
            placeholder="Enter a value"
          />
        </div>

        <div style={styles.buttonGroup}>
          <button
            onClick={() => void handleDbPut()}
            disabled={!connected}
            style={{ ...styles.button, ...(connected ? {} : styles.buttonDisabled) }}
          >
            Store
          </button>
          <button
            onClick={() => void handleDbGet()}
            disabled={!connected}
            style={{ ...styles.button, ...(connected ? {} : styles.buttonDisabled) }}
          >
            Retrieve
          </button>
        </div>

        {dbValue !== null && (
          <div style={styles.result}>
            Retrieved: <code style={styles.code}>{dbValue}</code>
          </div>
        )}
      </div>
    </div>
  );
}
