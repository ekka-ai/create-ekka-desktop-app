/**
 * Asynchronous Work Page
 * Queue operations demo with dark mode support
 */

import { type CSSProperties, type ReactElement } from 'react';
import { ekka, EkkaError } from '../../ekka';

interface AsyncWorkProps {
  connected: boolean;
  queueKind: string;
  queuePayload: string;
  queueJobId: string | null;
  onKindChange: (kind: string) => void;
  onPayloadChange: (payload: string) => void;
  onJobIdChange: (jobId: string | null) => void;
  onError: (error: string | null) => void;
  darkMode: boolean;
}

export function AsyncWork({
  connected,
  queueKind,
  queuePayload,
  queueJobId,
  onKindChange,
  onPayloadChange,
  onJobIdChange,
  onError,
  darkMode,
}: AsyncWorkProps): ReactElement {
  async function handleQueueEnqueue(): Promise<void> {
    try {
      const payload: unknown = JSON.parse(queuePayload);
      const jobId = await ekka.queue.enqueue(queueKind, payload);
      onJobIdChange(jobId);
      onError(null);
    } catch (err: unknown) {
      const message = err instanceof EkkaError ? err.message : 'Unknown error';
      onError(message);
    }
  }

  async function handleQueueClaim(): Promise<void> {
    try {
      const job = await ekka.queue.claim();
      if (job) {
        onJobIdChange(job.id);
        onError(null);
        await ekka.queue.ack(job);
      } else {
        onJobIdChange(null);
        onError('No jobs in queue');
      }
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
    inputWide: {
      width: '100%',
      maxWidth: '400px',
      padding: '8px 12px',
      fontSize: '13px',
      fontFamily: 'SF Mono, Monaco, Consolas, monospace',
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
        <h1 style={styles.title}>Asynchronous Work</h1>
        <p style={styles.description}>
          Manage long-running tasks through job queues.
        </p>
      </header>

      <div style={styles.card}>
        <div style={styles.formGroup}>
          <label style={styles.label}>Job Type</label>
          <input
            type="text"
            value={queueKind}
            onChange={(e) => onKindChange(e.target.value)}
            style={styles.input}
            placeholder="Job type"
          />
        </div>

        <div style={styles.formGroup}>
          <label style={styles.label}>Payload (JSON)</label>
          <input
            type="text"
            value={queuePayload}
            onChange={(e) => onPayloadChange(e.target.value)}
            style={styles.inputWide}
            placeholder='{"key": "value"}'
          />
        </div>

        <div style={styles.buttonGroup}>
          <button
            onClick={() => void handleQueueEnqueue()}
            disabled={!connected}
            style={{ ...styles.button, ...(connected ? {} : styles.buttonDisabled) }}
          >
            Enqueue
          </button>
          <button
            onClick={() => void handleQueueClaim()}
            disabled={!connected}
            style={{ ...styles.button, ...(connected ? {} : styles.buttonDisabled) }}
          >
            Claim & Complete
          </button>
        </div>

        {queueJobId && (
          <div style={styles.result}>
            Job processed: <code style={styles.code}>{queueJobId}</code>
          </div>
        )}
      </div>
    </div>
  );
}
