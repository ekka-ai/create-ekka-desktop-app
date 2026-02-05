/**
 * Documentation Generation Page
 *
 * V2 EXECUTION RUNS ONLY - No V1/Temporal fallback.
 * - Uses POST /engine/execution/runs (V2)
 * - Status from GET /engine/admin/execution/runs/{id}
 * - Legacy V1 runs are hidden (not fetched)
 */

import { useState, useEffect, useRef, type CSSProperties, type ReactElement } from 'react';
import {
  startExecutionRun,
  getExecutionRun,
  DOCGEN_BASIC_PLAN_ID,
  type ExecutionRun,
} from '../../ekka/ops/executionRuns';

// =============================================================================
// TYPES
// =============================================================================

interface DocGenPageProps {
  darkMode: boolean;
  persistedState?: { runId: string | null; folder: string | null };
  onStateChange?: (state: { runId: string | null; folder: string | null }) => void;
}

// V2 only - no legacy types
interface RunWithStatus {
  id: string;
  run: ExecutionRun | null;
  loading: boolean;
  error: string | null;
  isLegacy?: boolean; // Flag for pre-V2 runs (hidden from UI)
}

const STORAGE_KEY = 'ekka.docgen.runs';
const MAX_RUNS = 10;

// =============================================================================
// HELPERS
// =============================================================================

function loadRunIds(): string[] {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      const parsed = JSON.parse(saved) as string[];
      return Array.isArray(parsed) ? parsed.slice(0, MAX_RUNS) : [];
    }
  } catch {
    // Ignore parse errors
  }
  return [];
}

function saveRunIds(ids: string[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(ids.slice(0, MAX_RUNS)));
  } catch {
    // Ignore storage errors
  }
}

function formatDate(dateStr: string): string {
  try {
    const date = new Date(dateStr);
    return date.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return dateStr;
  }
}

function shortId(id: string): string {
  return id.slice(0, 8);
}

// Helper to extract output text from V2 execution run
function getOutputText(run: ExecutionRun | null): string | undefined {
  if (!run?.result) return undefined;

  const result = run.result as Record<string, unknown>;

  // V2 ExecutionRun has result.result.output_text (from task output)
  if (result.result && typeof result.result === 'object') {
    const inner = result.result as Record<string, unknown>;
    if ('output_text' in inner) {
      return inner.output_text as string | undefined;
    }
  }

  // Also try direct output_text on result
  if ('output_text' in result) {
    return result.output_text as string | undefined;
  }

  return undefined;
}

// =============================================================================
// MAIN COMPONENT
// =============================================================================

export function DocGenPage({ darkMode, persistedState, onStateChange }: DocGenPageProps): ReactElement {
  // Folder selection
  const [selectedFolder, setSelectedFolder] = useState<string | null>(persistedState?.folder ?? null);

  // Run IDs list (persisted to localStorage)
  const [runIds, setRunIds] = useState<string[]>(() => {
    // Migrate from old single-run state if present
    const oldRunId = persistedState?.runId;
    const existingIds = loadRunIds();
    if (oldRunId && !existingIds.includes(oldRunId)) {
      const newIds = [oldRunId, ...existingIds].slice(0, MAX_RUNS);
      saveRunIds(newIds);
      return newIds;
    }
    return existingIds;
  });

  // Run statuses (fetched from backend)
  const [runs, setRuns] = useState<Map<string, RunWithStatus>>(new Map());

  // UI state
  const [error, setError] = useState<string | null>(null);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [copySuccess, setCopySuccess] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Debounce for Generate button
  const generateDebounceRef = useRef(false);

  // Colors
  const colors = {
    text: darkMode ? '#ffffff' : '#1d1d1f',
    textMuted: darkMode ? '#98989d' : '#6e6e73',
    textDim: darkMode ? '#636366' : '#aeaeb2',
    bg: darkMode ? '#2c2c2e' : '#fafafa',
    bgAlt: darkMode ? '#1c1c1e' : '#ffffff',
    bgInput: darkMode ? '#3a3a3c' : '#ffffff',
    border: darkMode ? '#3a3a3c' : '#e5e5e5',
    accent: darkMode ? '#0a84ff' : '#007aff',
    green: darkMode ? '#30d158' : '#34c759',
    orange: darkMode ? '#ff9f0a' : '#ff9500',
    red: darkMode ? '#ff453a' : '#ff3b30',
    purple: darkMode ? '#bf5af2' : '#af52de',
  };

  const styles: Record<string, CSSProperties> = {
    container: {
      width: '100%',
      maxWidth: '900px',
    },
    header: {
      marginBottom: '32px',
    },
    title: {
      fontSize: '28px',
      fontWeight: 700,
      color: colors.text,
      marginBottom: '8px',
      letterSpacing: '-0.02em',
    },
    subtitle: {
      fontSize: '14px',
      color: colors.textMuted,
      lineHeight: 1.6,
      maxWidth: '600px',
    },
    section: {
      marginBottom: '28px',
    },
    sectionHeader: {
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      marginBottom: '12px',
    },
    sectionTitle: {
      fontSize: '11px',
      fontWeight: 600,
      color: colors.textMuted,
      textTransform: 'uppercase' as const,
      letterSpacing: '0.05em',
    },
    sectionLine: {
      flex: 1,
      height: '1px',
      background: colors.border,
    },
    card: {
      background: colors.bg,
      border: `1px solid ${colors.border}`,
      borderRadius: '12px',
      padding: '20px',
    },
    folderSelector: {
      display: 'flex',
      gap: '12px',
      alignItems: 'center',
    },
    selectedFolderBox: {
      flex: 1,
      padding: '12px 16px',
      background: colors.bgInput,
      border: `1px solid ${colors.border}`,
      borderRadius: '8px',
      fontSize: '13px',
      fontFamily: 'SF Mono, Monaco, Consolas, monospace',
      color: colors.text,
      overflow: 'hidden',
      textOverflow: 'ellipsis',
      whiteSpace: 'nowrap' as const,
    },
    placeholderText: {
      color: colors.textMuted,
      fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Text", system-ui, sans-serif',
    },
    button: {
      padding: '10px 20px',
      fontSize: '13px',
      fontWeight: 600,
      color: '#ffffff',
      background: colors.accent,
      border: 'none',
      borderRadius: '8px',
      cursor: 'pointer',
      transition: 'opacity 0.15s ease',
      whiteSpace: 'nowrap' as const,
    },
    buttonSecondary: {
      padding: '10px 20px',
      fontSize: '13px',
      fontWeight: 600,
      color: colors.accent,
      background: darkMode ? 'rgba(10, 132, 255, 0.15)' : 'rgba(0, 122, 255, 0.1)',
      border: 'none',
      borderRadius: '8px',
      cursor: 'pointer',
      transition: 'opacity 0.15s ease',
      whiteSpace: 'nowrap' as const,
    },
    buttonSmall: {
      padding: '6px 12px',
      fontSize: '12px',
      fontWeight: 500,
      color: colors.accent,
      background: 'transparent',
      border: `1px solid ${colors.border}`,
      borderRadius: '6px',
      cursor: 'pointer',
    },
    buttonDisabled: {
      opacity: 0.5,
      cursor: 'not-allowed',
    },
    error: {
      marginBottom: '20px',
      padding: '12px 14px',
      background: darkMode ? '#3c1618' : '#fef2f2',
      border: `1px solid ${darkMode ? '#7f1d1d' : '#fecaca'}`,
      borderRadius: '8px',
      fontSize: '13px',
      color: darkMode ? '#fca5a5' : '#991b1b',
    },
    table: {
      width: '100%',
      borderCollapse: 'collapse' as const,
      fontSize: '13px',
    },
    th: {
      textAlign: 'left' as const,
      padding: '10px 12px',
      borderBottom: `1px solid ${colors.border}`,
      color: colors.textMuted,
      fontWeight: 600,
      fontSize: '11px',
      textTransform: 'uppercase' as const,
      letterSpacing: '0.05em',
    },
    td: {
      padding: '12px',
      borderBottom: `1px solid ${colors.border}`,
      color: colors.text,
    },
    statusBadge: {
      display: 'inline-flex',
      alignItems: 'center',
      gap: '4px',
      padding: '4px 8px',
      borderRadius: '4px',
      fontSize: '11px',
      fontWeight: 600,
    },
    outputCard: {
      background: colors.bg,
      border: `1px solid ${colors.border}`,
      borderRadius: '12px',
      overflow: 'hidden',
    },
    outputHeader: {
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '12px 16px',
      borderBottom: `1px solid ${colors.border}`,
      background: darkMode ? 'rgba(255, 255, 255, 0.02)' : 'rgba(0, 0, 0, 0.02)',
    },
    outputContent: {
      padding: '20px',
      maxHeight: '400px',
      overflowY: 'auto' as const,
      fontSize: '14px',
      lineHeight: 1.7,
      color: colors.text,
      whiteSpace: 'pre-wrap' as const,
      fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Text", system-ui, sans-serif',
    },
    emptyState: {
      padding: '40px 20px',
      textAlign: 'center' as const,
      color: colors.textMuted,
      fontSize: '14px',
    },
  };

  // Fetch status for all runs on mount and when runIds changes
  useEffect(() => {
    if (runIds.length > 0) {
      void fetchAllRunStatuses();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- Only re-fetch when runIds list changes
  }, [runIds.length]);

  // Sync folder to parent state
  useEffect(() => {
    onStateChange?.({ runId: null, folder: selectedFolder });
    // eslint-disable-next-line react-hooks/exhaustive-deps -- Only sync when folder changes
  }, [selectedFolder]);

  // Fetch status for all runs (V2 only - no V1 fallback)
  const fetchAllRunStatuses = async () => {
    setIsRefreshing(true);

    const newRuns = new Map<string, RunWithStatus>();
    const legacyIds: string[] = [];

    await Promise.all(
      runIds.map(async (id) => {
        try {
          const run = await getExecutionRun(id);
          newRuns.set(id, { id, run, loading: false, error: null });
        } catch (err) {
          const message = err instanceof Error ? err.message : 'Failed to fetch';
          // Only treat as legacy if it's a 404 (not found) - other errors keep the entry
          const isNotFound = message.includes('404') || message.includes('not found') || message.includes('Not Found');
          if (isNotFound) {
            // Legacy V1 run - mark for removal
            legacyIds.push(id);
          } else {
            // Network/server error - keep entry with error state
            newRuns.set(id, { id, run: null, loading: false, error: message });
          }
        }
      })
    );

    // Auto-clean legacy V1 run IDs from storage (they're dead, no point keeping them)
    if (legacyIds.length > 0) {
      const cleanedIds = runIds.filter(id => !legacyIds.includes(id));
      setRunIds(cleanedIds);
      saveRunIds(cleanedIds);
    }

    setRuns(newRuns);
    setIsRefreshing(false);
  };

  // Handle folder selection
  const handleSelectFolder = async () => {
    setError(null);
    try {
      const { open } = await import('@tauri-apps/plugin-dialog');
      const selected = await open({ directory: true, multiple: false });
      if (selected && typeof selected === 'string') {
        setSelectedFolder(selected);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setError(`Failed to open folder picker: ${message}`);
    }
  };

  // Handle generate - STATELESS action (V2 Execution Plan API)
  const handleGenerate = async () => {
    if (!selectedFolder) return;

    // Debounce: prevent double-click
    if (generateDebounceRef.current) return;
    generateDebounceRef.current = true;
    setTimeout(() => { generateDebounceRef.current = false; }, 500);

    setError(null);

    try {
      // V2: Use execution plan run-start API
      const response = await startExecutionRun({
        plan_id: DOCGEN_BASIC_PLAN_ID,
        inputs: {
          input: selectedFolder,
        },
      });

      const runId = response.run_id;

      // Add new run ID to list (newest first)
      const newIds = [runId, ...runIds.filter(id => id !== runId)].slice(0, MAX_RUNS);
      setRunIds(newIds);
      saveRunIds(newIds);

      // Add initial status for new run
      setRuns(prev => {
        const newMap = new Map(prev);
        newMap.set(runId, {
          id: runId,
          run: {
            id: runId,
            plan_id: DOCGEN_BASIC_PLAN_ID,
            plan_identity: 'system/ekka/docgen.basic@1.0.0',
            status: 'running',
            current_step_index: 0,
            total_steps: 1,
            completed_steps: 0,
            progress: 0,
            created_at: new Date().toISOString(),
          } as ExecutionRun,
          loading: false,
          error: null,
        });
        return newMap;
      });

      // Immediately fetch actual status
      try {
        const run = await getExecutionRun(runId);
        setRuns(prev => {
          const newMap = new Map(prev);
          newMap.set(runId, { id: runId, run, loading: false, error: null });
          return newMap;
        });
      } catch {
        // Ignore - will be fetched on next refresh
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to start generation';
      setError(message);
    }
  };

  // Handle refresh
  const handleRefresh = () => {
    void fetchAllRunStatuses();
  };

  // Handle view result
  const handleViewResult = (runId: string) => {
    setSelectedRunId(selectedRunId === runId ? null : runId);
  };

  // Handle retry (create new run for same folder)
  const handleRetry = () => {
    void handleGenerate();
  };

  // Copy output to clipboard
  const handleCopyOutput = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopySuccess(true);
      setTimeout(() => setCopySuccess(false), 2000);
    } catch {
      setError('Failed to copy to clipboard');
    }
  };

  // Get status badge style
  const getStatusStyle = (status: string): CSSProperties => {
    switch (status) {
      case 'completed':
        return {
          background: darkMode ? 'rgba(48, 209, 88, 0.15)' : 'rgba(52, 199, 89, 0.12)',
          color: colors.green,
        };
      case 'failed':
        return {
          background: darkMode ? 'rgba(255, 69, 58, 0.15)' : 'rgba(255, 59, 48, 0.12)',
          color: colors.red,
        };
      case 'running':
        return {
          background: darkMode ? 'rgba(10, 132, 255, 0.15)' : 'rgba(0, 122, 255, 0.1)',
          color: colors.accent,
        };
      default: // pending, dispatched, queued
        return {
          background: darkMode ? 'rgba(255, 159, 10, 0.15)' : 'rgba(255, 149, 0, 0.12)',
          color: colors.orange,
        };
    }
  };

  // Get display status
  const getDisplayStatus = (status: string): string => {
    switch (status) {
      case 'pending':
      case 'dispatched':
        return 'Queued';
      case 'running':
        return 'Running';
      case 'completed':
        return 'Complete';
      case 'failed':
        return 'Failed';
      case 'cancelled':
        return 'Cancelled';
      default:
        return status;
    }
  };

  const selectedRun = selectedRunId ? runs.get(selectedRunId) : null;
  const canGenerate = !!selectedFolder;

  return (
    <div style={styles.container}>
      <header style={styles.header}>
        <h1 style={styles.title}>Generate Documentation</h1>
        <p style={styles.subtitle}>
          Select a source folder to automatically generate documentation using AI.
        </p>
      </header>

      {error && <div style={styles.error}>{error}</div>}

      {/* Section: Folder Selection & Generate */}
      <div style={styles.section}>
        <div style={styles.sectionHeader}>
          <span style={styles.sectionTitle}>Source Folder</span>
          <div style={styles.sectionLine} />
        </div>
        <div style={styles.card}>
          <div style={styles.folderSelector}>
            <div style={styles.selectedFolderBox}>
              {selectedFolder ? (
                selectedFolder
              ) : (
                <span style={styles.placeholderText}>No folder selected</span>
              )}
            </div>
            <button
              onClick={() => void handleSelectFolder()}
              style={styles.buttonSecondary}
            >
              Browse...
            </button>
          </div>

          <div style={{ marginTop: '16px' }}>
            <button
              onClick={() => void handleGenerate()}
              style={{
                ...styles.button,
                ...(!canGenerate ? styles.buttonDisabled : {}),
              }}
              disabled={!canGenerate}
            >
              Generate Documentation
            </button>
          </div>
        </div>
      </div>

      {/* Section: Runs Table */}
      <div style={styles.section}>
        <div style={styles.sectionHeader}>
          <span style={styles.sectionTitle}>Execution Runs</span>
          <div style={styles.sectionLine} />
          <button
            onClick={handleRefresh}
            style={{
              ...styles.buttonSmall,
              opacity: isRefreshing ? 0.5 : 1,
            }}
            disabled={isRefreshing}
          >
            {isRefreshing ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
        <div style={styles.card}>
          {runIds.length === 0 ? (
            <div style={styles.emptyState}>
              No runs yet. Click "Generate Documentation" to start.
            </div>
          ) : (
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>Run ID</th>
                  <th style={styles.th}>Created</th>
                  <th style={styles.th}>Status</th>
                  <th style={styles.th}>Progress</th>
                  <th style={styles.th}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {runIds.map((id) => {
                  const runData = runs.get(id);
                  const run = runData?.run;
                  const status = run?.status ?? 'pending';
                  const progress = run?.progress ?? 0;
                  const createdAt = run?.created_at ?? '';
                  const isComplete = status === 'completed';
                  const isFailed = status === 'failed';
                  const isSelected = selectedRunId === id;

                  return (
                    <tr key={id} style={{ background: isSelected ? (darkMode ? 'rgba(10, 132, 255, 0.1)' : 'rgba(0, 122, 255, 0.05)') : 'transparent' }}>
                      <td style={{ ...styles.td, fontFamily: 'monospace', fontSize: '12px' }}>
                        {shortId(id)}
                      </td>
                      <td style={{ ...styles.td, color: colors.textMuted }}>
                        {createdAt ? formatDate(createdAt) : '—'}
                      </td>
                      <td style={styles.td}>
                        <span style={{ ...styles.statusBadge, ...getStatusStyle(status) }}>
                          {getDisplayStatus(status)}
                        </span>
                      </td>
                      <td style={{ ...styles.td, color: colors.textMuted }}>
                        {progress > 0 && progress < 100 ? `${progress}%` : '—'}
                      </td>
                      <td style={styles.td}>
                        <div style={{ display: 'flex', gap: '8px' }}>
                          {isComplete && (
                            <button
                              onClick={() => handleViewResult(id)}
                              style={styles.buttonSmall}
                            >
                              {isSelected ? 'Hide' : 'View'}
                            </button>
                          )}
                          {isFailed && (
                            <button
                              onClick={() => handleViewResult(id)}
                              style={styles.buttonSmall}
                            >
                              {isSelected ? 'Hide' : 'Details'}
                            </button>
                          )}
                          <button
                            onClick={handleRetry}
                            style={styles.buttonSmall}
                          >
                            Retry
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Section: Selected Run Output */}
      {selectedRun?.run && selectedRun.run.status === 'completed' && getOutputText(selectedRun.run) && (
        <div style={styles.section}>
          <div style={styles.sectionHeader}>
            <span style={styles.sectionTitle}>Generated Documentation</span>
            <div style={styles.sectionLine} />
          </div>
          <div style={styles.outputCard}>
            <div style={styles.outputHeader}>
              <span style={{ fontSize: '12px', color: colors.textMuted }}>
                Run: {shortId(selectedRun.id)}
              </span>
              <button
                onClick={() => void handleCopyOutput(getOutputText(selectedRun.run) ?? '')}
                style={styles.buttonSmall}
              >
                {copySuccess ? 'Copied!' : 'Copy'}
              </button>
            </div>
            <div style={styles.outputContent}>
              {getOutputText(selectedRun.run)}
            </div>
          </div>
        </div>
      )}

      {/* Section: Selected Run Error */}
      {selectedRun?.run && selectedRun.run.status === 'failed' && (
        <div style={styles.section}>
          <div style={styles.sectionHeader}>
            <span style={styles.sectionTitle}>Error Details</span>
            <div style={styles.sectionLine} />
          </div>
          <div style={{ ...styles.card, borderColor: colors.red }}>
            <div style={{ marginBottom: '8px' }}>
              <span style={{ ...styles.statusBadge, ...getStatusStyle('failed') }}>
                ERROR
              </span>
            </div>
            <p style={{ fontSize: '14px', color: colors.text, margin: 0 }}>
              {selectedRun.run.error || 'An unknown error occurred'}
            </p>
          </div>
        </div>
      )}

    </div>
  );
}

