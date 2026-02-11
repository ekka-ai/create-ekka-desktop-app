/**
 * Fatal Error Screen
 *
 * Shown when engine connection fails and app cannot proceed.
 * Displays error details and suggested recovery steps.
 */

import { useState, type ReactElement, type CSSProperties } from 'react';
import type { BackendInitError } from '../../ekka/internal/backend';

interface FatalErrorScreenProps {
  error: BackendInitError;
  darkMode: boolean;
}

export function FatalErrorScreen({ error, darkMode }: FatalErrorScreenProps): ReactElement {
  const [copied, setCopied] = useState(false);

  const colors = {
    bg: darkMode ? '#1c1c1e' : '#ffffff',
    cardBg: darkMode ? '#2c2c2e' : '#f5f5f7',
    border: darkMode ? '#3a3a3c' : '#e5e5e5',
    text: darkMode ? '#ffffff' : '#1d1d1f',
    textMuted: darkMode ? '#98989d' : '#86868b',
    errorBg: darkMode ? '#3c1618' : '#fef2f2',
    errorBorder: darkMode ? '#7f1d1d' : '#fecaca',
    errorText: darkMode ? '#fca5a5' : '#991b1b',
    buttonBg: darkMode ? '#3a3a3c' : '#e5e5e5',
    buttonHover: darkMode ? '#48484a' : '#d1d1d6',
    code: darkMode ? '#1c1c1e' : '#f5f5f7',
  };

  const styles: Record<string, CSSProperties> = {
    container: {
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      minHeight: '100vh',
      background: colors.bg,
      fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Text", system-ui, sans-serif',
      padding: '20px',
    },
    card: {
      width: '100%',
      maxWidth: '600px',
      padding: '32px',
      background: colors.cardBg,
      borderRadius: '12px',
      border: `1px solid ${colors.border}`,
    },
    title: {
      fontSize: '20px',
      fontWeight: 600,
      color: colors.errorText,
      marginBottom: '8px',
    },
    subtitle: {
      fontSize: '14px',
      color: colors.textMuted,
      marginBottom: '24px',
    },
    section: {
      marginBottom: '20px',
    },
    sectionTitle: {
      fontSize: '13px',
      fontWeight: 600,
      color: colors.text,
      marginBottom: '8px',
    },
    errorBox: {
      padding: '12px',
      background: colors.errorBg,
      border: `1px solid ${colors.errorBorder}`,
      borderRadius: '6px',
      marginBottom: '12px',
    },
    errorMessage: {
      fontSize: '13px',
      color: colors.errorText,
      fontFamily: 'SF Mono, Monaco, monospace',
      wordBreak: 'break-word',
    },
    codeBlock: {
      padding: '12px',
      background: colors.code,
      border: `1px solid ${colors.border}`,
      borderRadius: '6px',
      fontSize: '12px',
      fontFamily: 'SF Mono, Monaco, monospace',
      color: colors.textMuted,
      overflowX: 'auto',
      whiteSpace: 'pre-wrap',
      wordBreak: 'break-word',
    },
    stepsList: {
      margin: '0',
      paddingLeft: '20px',
      fontSize: '13px',
      color: colors.text,
      lineHeight: '1.6',
    },
    button: {
      padding: '10px 16px',
      fontSize: '13px',
      fontWeight: 500,
      color: colors.text,
      background: colors.buttonBg,
      border: 'none',
      borderRadius: '6px',
      cursor: 'pointer',
      transition: 'background 0.15s ease',
    },
  };

  function handleCopyDetails(): void {
    const details = JSON.stringify(error, null, 2);
    navigator.clipboard.writeText(details).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <div style={styles.title}>Engine Connection Failed</div>
        <div style={styles.subtitle}>
          The desktop app could not connect to the EKKA engine.
        </div>

        <div style={styles.section}>
          <div style={styles.sectionTitle}>Error Details</div>
          <div style={styles.errorBox}>
            <div style={styles.errorMessage}>{error.error_message}</div>
          </div>
          <div style={styles.codeBlock}>
            <div>Operation: {error.op}</div>
            <div>Timestamp: {error.ts_timestamp}</div>
            <div>Correlation ID: {error.correlation_id}</div>
          </div>
        </div>

        {error.stack && (
          <div style={styles.section}>
            <div style={styles.sectionTitle}>Stack Trace</div>
            <div style={styles.codeBlock}>{error.stack}</div>
          </div>
        )}

        <div style={styles.section}>
          <div style={styles.sectionTitle}>Next Steps</div>
          <ol style={styles.stepsList}>
            <li>Check that EKKA_SECURITY_EPOCH=1 is set in .env.local</li>
            <li>Verify the app was started with <code>./start-dev.sh tauri</code></li>
            <li>Check terminal logs for Rust-side errors during startup</li>
            <li>Restart the app and check for [desktop.backend.init.failed] in console</li>
          </ol>
        </div>

        <button
          style={styles.button}
          onClick={handleCopyDetails}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = colors.buttonHover;
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = colors.buttonBg;
          }}
        >
          {copied ? 'Copied' : 'Copy Error Details'}
        </button>
      </div>
    </div>
  );
}
