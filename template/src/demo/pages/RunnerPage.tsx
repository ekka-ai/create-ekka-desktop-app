/**
 * Runner Page - Runner + Task Queue Observability
 *
 * Displays runner task stats to diagnose "workflow stuck" situations:
 * - Active runners (inferred from recent claims)
 * - Queue counts (pending, claimed, completed_5m, failed_5m)
 * - By subtype breakdown
 * - Recent tasks table
 *
 * Polls runner.taskStats() every 2 seconds while tab is open.
 * Stats are fetched via Rust proxy (no direct TS HTTP).
 */

import { useState, useEffect, useRef, type CSSProperties, type ReactElement } from 'react';
import { advanced, type RunnerTaskStats } from '../../ekka';

interface RunnerPageProps {
  darkMode: boolean;
}

// Fetch stats via Rust proxy (no direct HTTP from TS)
async function fetchStats(): Promise<RunnerTaskStats> {
  return advanced.runner.taskStats();
}

// =============================================================================
// HELPERS
// =============================================================================

function timeAgo(iso: string): string {
  try {
    const now = Date.now();
    const then = new Date(iso).getTime();
    const diffSec = Math.floor((now - then) / 1000);
    if (diffSec < 60) return `${diffSec}s ago`;
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
    if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
    return `${Math.floor(diffSec / 86400)}d ago`;
  } catch {
    return iso;
  }
}

function shortId(id: string | null): string {
  if (!id) return '-';
  return id.length > 8 ? `${id.slice(0, 8)}...` : id;
}

// =============================================================================
// COMPONENT
// =============================================================================

interface ErrorDetails {
  message: string;
  status?: number;
  statusText?: string;
  data?: unknown;
}

export function RunnerPage({ darkMode }: RunnerPageProps): ReactElement {
  const [stats, setStats] = useState<RunnerTaskStats | null>(null);
  const [error, setError] = useState<ErrorDetails | null>(null);
  const [showErrorDetails, setShowErrorDetails] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const pollingRef = useRef<number | null>(null);

  const colors = {
    text: darkMode ? '#ffffff' : '#1d1d1f',
    textMuted: darkMode ? '#98989d' : '#6e6e73',
    bg: darkMode ? '#2c2c2e' : '#fafafa',
    bgAlt: darkMode ? '#1c1c1e' : '#ffffff',
    border: darkMode ? '#3a3a3c' : '#e5e5e5',
    green: darkMode ? '#30d158' : '#34c759',
    yellow: darkMode ? '#ffd60a' : '#ffcc00',
    blue: darkMode ? '#0a84ff' : '#007aff',
    red: darkMode ? '#ff453a' : '#ff3b30',
  };

  const styles: Record<string, CSSProperties> = {
    container: { width: '100%', maxWidth: '1000px' },
    header: { marginBottom: '24px' },
    title: {
      fontSize: '28px',
      fontWeight: 700,
      color: colors.text,
      marginBottom: '4px',
      letterSpacing: '-0.02em',
    },
    subtitle: {
      fontSize: '13px',
      color: colors.textMuted,
      display: 'flex',
      alignItems: 'center',
      gap: '12px',
    },
    refreshBadge: {
      background: colors.green,
      color: '#fff',
      padding: '2px 8px',
      borderRadius: '4px',
      fontSize: '11px',
      fontWeight: 600,
    },
    grid: {
      display: 'grid',
      gridTemplateColumns: '1fr 1fr',
      gap: '16px',
      marginBottom: '16px',
    },
    card: {
      background: colors.bg,
      border: `1px solid ${colors.border}`,
      borderRadius: '12px',
      padding: '16px',
    },
    cardTitle: {
      fontSize: '12px',
      fontWeight: 600,
      color: colors.textMuted,
      marginBottom: '12px',
      textTransform: 'uppercase' as const,
      letterSpacing: '0.03em',
    },
    countGrid: {
      display: 'grid',
      gridTemplateColumns: 'repeat(4, 1fr)',
      gap: '8px',
    },
    countItem: {
      textAlign: 'center' as const,
    },
    countValue: {
      fontSize: '24px',
      fontWeight: 700,
    },
    countLabel: {
      fontSize: '11px',
      color: colors.textMuted,
    },
    runnerList: {
      listStyle: 'none',
      padding: 0,
      margin: 0,
    },
    runnerItem: {
      display: 'flex',
      justifyContent: 'space-between',
      padding: '6px 0',
      fontSize: '13px',
      borderBottom: `1px solid ${colors.border}`,
    },
    noRunners: {
      background: darkMode ? '#3c1618' : '#fef2f2',
      border: `1px solid ${darkMode ? '#7f1d1d' : '#fecaca'}`,
      borderRadius: '8px',
      padding: '12px',
      color: darkMode ? '#fca5a5' : '#991b1b',
      fontSize: '13px',
    },
    hasRunners: {
      background: darkMode ? '#14532d' : '#f0fdf4',
      border: `1px solid ${darkMode ? '#166534' : '#bbf7d0'}`,
      borderRadius: '8px',
      padding: '12px',
    },
    warning: {
      background: darkMode ? '#7f1d1d' : '#fef2f2',
      border: `1px solid ${darkMode ? '#991b1b' : '#fecaca'}`,
      borderRadius: '8px',
      padding: '12px',
      marginBottom: '16px',
      color: darkMode ? '#fca5a5' : '#991b1b',
      fontSize: '13px',
      fontWeight: 500,
    },
    table: {
      width: '100%',
      borderCollapse: 'collapse' as const,
      fontSize: '12px',
    },
    th: {
      textAlign: 'left' as const,
      padding: '8px 12px',
      borderBottom: `1px solid ${colors.border}`,
      color: colors.textMuted,
      fontWeight: 600,
      fontSize: '11px',
      textTransform: 'uppercase' as const,
    },
    td: {
      padding: '8px 12px',
      borderBottom: `1px solid ${colors.border}`,
      color: colors.text,
    },
    statusBadge: {
      padding: '2px 8px',
      borderRadius: '4px',
      fontSize: '11px',
      fontWeight: 600,
    },
    error: {
      background: darkMode ? '#3c1618' : '#fef2f2',
      border: `1px solid ${darkMode ? '#7f1d1d' : '#fecaca'}`,
      borderRadius: '8px',
      padding: '12px',
      color: darkMode ? '#fca5a5' : '#991b1b',
      fontSize: '13px',
      marginBottom: '16px',
    },
  };

  const loadStats = async () => {
    try {
      const data = await fetchStats();
      setStats(data);
      setLastUpdated(new Date());
      setError(null);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to load stats';
      setError({
        message: errorMessage,
        status: undefined,
        statusText: undefined,
        data: undefined,
      });
    }
  };

  useEffect(() => {
    loadStats();
    pollingRef.current = window.setInterval(loadStats, 2000);
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, []);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'pending': return { bg: colors.yellow, text: '#000' };
      case 'claimed': return { bg: colors.blue, text: '#fff' };
      case 'completed': return { bg: colors.green, text: '#fff' };
      case 'failed': return { bg: colors.red, text: '#fff' };
      default: return { bg: colors.border, text: colors.text };
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <h1 style={styles.title}>Runner</h1>
        <div style={styles.subtitle}>
          <span>Task queue observability</span>
          <span style={styles.refreshBadge}>Auto-refresh: 2s</span>
          {lastUpdated && <span>Updated: {lastUpdated.toLocaleTimeString()}</span>}
        </div>
      </div>

      {error && (
        <div style={styles.error}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <strong>Error:</strong> {error.message}
              {error.status && (
                <span style={{ marginLeft: '8px', opacity: 0.8 }}>
                  (HTTP {error.status}{error.statusText ? `: ${error.statusText}` : ''})
                </span>
              )}
            </div>
            {error.data !== undefined && error.data !== null && (
              <button
                onClick={() => setShowErrorDetails(!showErrorDetails)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'inherit',
                  cursor: 'pointer',
                  fontSize: '12px',
                  textDecoration: 'underline',
                }}
              >
                {showErrorDetails ? 'Hide details' : 'Show details'}
              </button>
            )}
          </div>
          {showErrorDetails && error.data !== undefined && error.data !== null && (
            <pre style={{
              marginTop: '8px',
              padding: '8px',
              background: darkMode ? 'rgba(0,0,0,0.3)' : 'rgba(0,0,0,0.05)',
              borderRadius: '4px',
              fontSize: '11px',
              overflow: 'auto',
              maxHeight: '200px',
            }}>
              {JSON.stringify(error.data, null, 2)}
            </pre>
          )}
        </div>
      )}

      {stats && (
        <>
          {/* Warning if pending but no runners */}
          {stats.counts.pending > 0 && stats.active_runners.length === 0 && (
            <div style={styles.warning}>
              {stats.counts.pending} task(s) pending but no active runners detected.
              Workflows will be stuck until a runner starts polling.
            </div>
          )}

          <div style={styles.grid}>
            {/* Active Runners */}
            <div style={styles.card}>
              <div style={styles.cardTitle}>Active Runners</div>
              {stats.active_runners.length === 0 ? (
                <div style={styles.noRunners}>
                  No active runners detected (last 10m)
                </div>
              ) : (
                <div style={styles.hasRunners}>
                  <ul style={styles.runnerList}>
                    {stats.active_runners.map((r) => (
                      <li key={r.runner_id} style={styles.runnerItem}>
                        <span style={{ fontFamily: 'monospace' }}>{shortId(r.runner_id)}</span>
                        <span style={{ color: colors.textMuted }}>
                          last claimed {timeAgo(r.last_claimed_at)}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            {/* Queue Counts */}
            <div style={styles.card}>
              <div style={styles.cardTitle}>Queue Counts</div>
              <div style={styles.countGrid}>
                <div style={styles.countItem}>
                  <div style={{ ...styles.countValue, color: stats.counts.pending > 0 ? colors.yellow : colors.textMuted }}>
                    {stats.counts.pending}
                  </div>
                  <div style={styles.countLabel}>Pending</div>
                </div>
                <div style={styles.countItem}>
                  <div style={{ ...styles.countValue, color: stats.counts.claimed > 0 ? colors.blue : colors.textMuted }}>
                    {stats.counts.claimed}
                  </div>
                  <div style={styles.countLabel}>Claimed</div>
                </div>
                <div style={styles.countItem}>
                  <div style={{ ...styles.countValue, color: stats.counts.completed_5m > 0 ? colors.green : colors.textMuted }}>
                    {stats.counts.completed_5m}
                  </div>
                  <div style={styles.countLabel}>Completed (5m)</div>
                </div>
                <div style={styles.countItem}>
                  <div style={{ ...styles.countValue, color: stats.counts.failed_5m > 0 ? colors.red : colors.textMuted }}>
                    {stats.counts.failed_5m}
                  </div>
                  <div style={styles.countLabel}>Failed (5m)</div>
                </div>
              </div>
            </div>
          </div>

          {/* By Capability */}
          {Object.keys(stats.by_capability || {}).length > 0 && (
            <div style={{ ...styles.card, marginBottom: '16px' }}>
              <div style={styles.cardTitle}>By Capability</div>
              <table style={styles.table}>
                <thead>
                  <tr>
                    <th style={styles.th}>Capability</th>
                    <th style={{ ...styles.th, textAlign: 'right' }}>Pending</th>
                    <th style={{ ...styles.th, textAlign: 'right' }}>Claimed</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(stats.by_capability || {}).map(([capability, data]) => (
                    <tr key={capability}>
                      <td style={{ ...styles.td, fontFamily: 'monospace' }}>{capability}</td>
                      <td style={{ ...styles.td, textAlign: 'right', color: data.pending > 0 ? colors.yellow : colors.textMuted }}>
                        {data.pending}
                      </td>
                      <td style={{ ...styles.td, textAlign: 'right', color: data.claimed > 0 ? colors.blue : colors.textMuted }}>
                        {data.claimed}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Recent Tasks */}
          <div style={styles.card}>
            <div style={styles.cardTitle}>Recent Tasks (25)</div>
            {stats.recent.length === 0 ? (
              <div style={{ color: colors.textMuted, fontSize: '13px' }}>No tasks found</div>
            ) : (
              <table style={styles.table}>
                <thead>
                  <tr>
                    <th style={styles.th}>Task ID</th>
                    <th style={styles.th}>Capability</th>
                    <th style={styles.th}>Status</th>
                    <th style={styles.th}>Runner</th>
                    <th style={styles.th}>Created</th>
                    <th style={styles.th}>Claimed</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.recent.map((t) => {
                    const statusColor = getStatusColor(t.status);
                    return (
                      <tr key={t.task_id}>
                        <td style={{ ...styles.td, fontFamily: 'monospace' }}>{shortId(t.task_id)}</td>
                        <td style={{ ...styles.td, fontFamily: 'monospace' }}>{t.capability_identity || 'unknown'}</td>
                        <td style={styles.td}>
                          <span style={{ ...styles.statusBadge, background: statusColor.bg, color: statusColor.text }}>
                            {t.status}
                          </span>
                        </td>
                        <td style={{ ...styles.td, fontFamily: 'monospace' }}>{shortId(t.claimed_by)}</td>
                        <td style={{ ...styles.td, color: colors.textMuted }}>{timeAgo(t.created_at)}</td>
                        <td style={{ ...styles.td, color: colors.textMuted }}>{t.claimed_at ? timeAgo(t.claimed_at) : '-'}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}

      {!stats && !error && (
        <div style={{ color: colors.textMuted, textAlign: 'center', padding: '40px' }}>
          Loading stats...
        </div>
      )}
    </div>
  );
}
