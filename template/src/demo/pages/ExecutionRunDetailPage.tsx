/**
 * Execution Run Detail Page
 *
 * Dedicated page for viewing a single execution run:
 * - Summary card (status, duration, progress, IDs)
 * - Context / Inputs JSON block
 * - Result / Outputs JSON block
 * - Admin-style timeline with expandable event payloads
 * - Refresh + Back navigation
 *
 * Uses existing execution.runs.get + execution.runs.events ops (no new endpoints).
 */

import { useState, useEffect, useRef, useCallback, type CSSProperties, type ReactElement } from 'react';
import { _internal, makeRequest } from '../../ekka/internal';
import { admin } from '../../ekka/ops';
import type { AdminLogEntry } from '../../ekka/ops/admin';

// =============================================================================
// PLAN TYPE (for Copy Plan JSON)
// =============================================================================

interface Plan {
  id: string;
  plan_code: string;
  display_name: string;
  classification?: string;
  description?: string;
  input_schema?: unknown;
  steps?: unknown[];
  [key: string]: unknown;
}

// =============================================================================
// API TYPES
// =============================================================================

interface Run {
  id: string;
  plan_id: string;
  plan_code?: string;
  status: string;
  progress?: number;
  correlation_id?: string;
  inputs?: Record<string, unknown>;
  context?: Record<string, unknown>;
  outputs?: Record<string, unknown>;
  result?: Record<string, unknown>;
  error?: string;
  duration_ms?: number;
  created_at: string;
  updated_at?: string;
  started_at?: string;
  completed_at?: string;
}

interface RunEvent {
  id: string;
  run_id: string;
  event_type: string;
  step_key?: string;
  step_index?: number;
  step_id?: string;
  capability_identity?: string;
  target_type?: string;
  target_id?: string;
  payload?: unknown;
  error_code?: string;
  error_message?: string;
  error_details?: unknown;
  duration_ms?: number;
  event_timestamp?: string;
  created_at: string;
}

// =============================================================================
// API HELPERS
// =============================================================================

async function request<T>(op: string, payload: unknown = {}): Promise<T> {
  const req = makeRequest(op, payload);
  const resp = await _internal.request(req);
  if (!resp.ok) {
    throw new Error(resp.error?.message || `${op} failed`);
  }
  return resp.result as T;
}

async function getRun(runId: string): Promise<Run> {
  const result = await request<{ run?: Run }>('execution.runs.get', { runId });
  return result.run || result as unknown as Run;
}

async function getRunEvents(runId: string): Promise<RunEvent[]> {
  const result = await request<{ data?: RunEvent[]; events?: RunEvent[] }>('execution.runs.events', { runId });
  return result.data || result.events || (Array.isArray(result) ? result as unknown as RunEvent[] : []);
}

async function getPlan(id: string): Promise<Plan> {
  const result = await request<{ plan?: Plan }>('execution.plans.get', { id });
  return result.plan || result as unknown as Plan;
}

// =============================================================================
// CLIPBOARD HELPER
// =============================================================================

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback: hidden textarea + execCommand
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand('copy');
      return true;
    } catch {
      return false;
    } finally {
      document.body.removeChild(ta);
    }
  }
}

// =============================================================================
// PAGE COMPONENT
// =============================================================================

interface ExecutionRunDetailPageProps {
  runId: string;
  onBack: () => void;
  darkMode: boolean;
}

export function ExecutionRunDetailPage({ runId, onBack, darkMode }: ExecutionRunDetailPageProps): ReactElement {
  const [run, setRun] = useState<Run | null>(null);
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [expandedEvents, setExpandedEvents] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copyStatus, setCopyStatus] = useState<string | null>(null);
  const [planCache, setPlanCache] = useState<Plan | null>(null);
  const [debugOpen, setDebugOpen] = useState(false);
  // Logs section state
  const [logsOpen, setLogsOpen] = useState(false);
  const [logsSince, setLogsSince] = useState('10m');
  const [logsService, setLogsService] = useState('');
  const [logsLimit, setLogsLimit] = useState(200);
  const [logEntries, setLogEntries] = useState<AdminLogEntry[]>([]);
  const [logsTotal, setLogsTotal] = useState(0);
  const [logsLoading, setLogsLoading] = useState(false);
  const [logsError, setLogsError] = useState<string | null>(null);
  const didLoadRef = useRef(false);
  const copyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const colors = {
    bg: darkMode ? '#1c1c1e' : '#ffffff',
    cardBg: darkMode ? '#2c2c2e' : '#fafafa',
    border: darkMode ? '#3a3a3c' : '#e5e5e5',
    text: darkMode ? '#ffffff' : '#1d1d1f',
    textMuted: darkMode ? '#98989d' : '#6e6e73',
    blue: darkMode ? '#0a84ff' : '#007aff',
    green: darkMode ? '#30d158' : '#34c759',
    red: darkMode ? '#ff453a' : '#ff3b30',
    yellow: darkMode ? '#ffd60a' : '#ff9f0a',
  };

  const styles: Record<string, CSSProperties> = {
    container: { padding: '24px 32px', maxWidth: '1000px', color: colors.text },
    card: { background: colors.cardBg, border: `1px solid ${colors.border}`, borderRadius: '8px', overflow: 'hidden', marginBottom: '16px' },
    label: { fontSize: '11px', fontWeight: 600, color: colors.textMuted, textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '4px', display: 'block' },
    mono: { fontFamily: 'SF Mono, Menlo, monospace', fontSize: '11px' },
    badge: { display: 'inline-block', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 500 },
    pre: { background: darkMode ? '#1c1c1e' : '#f5f5f7', border: `1px solid ${colors.border}`, borderRadius: '6px', padding: '12px', fontSize: '11px', fontFamily: 'SF Mono, Menlo, monospace', overflow: 'auto', maxHeight: '300px', whiteSpace: 'pre-wrap' as const, wordBreak: 'break-all' as const, margin: 0 },
    link: { color: colors.blue, cursor: 'pointer', background: 'none', border: 'none', fontSize: '12px', fontFamily: 'inherit', padding: 0 },
    error: { padding: '10px 14px', background: darkMode ? '#3c1618' : '#fef2f2', border: `1px solid ${darkMode ? '#7f1d1d' : '#fecaca'}`, borderRadius: '6px', fontSize: '13px', color: darkMode ? '#fca5a5' : '#991b1b', marginBottom: '16px' },
    button: { padding: '8px 20px', fontSize: '13px', fontWeight: 500, borderRadius: '6px', border: 'none', cursor: 'pointer' },
  };

  // Fetch run + events
  async function loadDetail() {
    setLoading(true);
    setError(null);
    setExpandedEvents(new Set());
    try {
      const r = await getRun(runId);
      setRun(r);
    } catch (e) {
      setError((e as Error).message);
      setLoading(false);
      return;
    }
    try {
      const ev = await getRunEvents(runId);
      setEvents(ev);
    } catch {
      // Events fetch failed — detail still visible
    }
    setLoading(false);
  }

  useEffect(() => {
    if (didLoadRef.current) return;
    didLoadRef.current = true;
    loadDetail();
  }, []);

  function toggleExpand(eventId: string) {
    setExpandedEvents((prev) => {
      const next = new Set(prev);
      if (next.has(eventId)) next.delete(eventId);
      else next.add(eventId);
      return next;
    });
  }

  // Show brief "Copied!" feedback
  const flashCopy = useCallback((label: string) => {
    setCopyStatus(label);
    if (copyTimerRef.current) clearTimeout(copyTimerRef.current);
    copyTimerRef.current = setTimeout(() => setCopyStatus(null), 1500);
  }, []);

  // Copy full plan + run + events JSON
  async function handleCopyPlanJson() {
    if (!run) return;
    let plan: Plan | null = planCache;
    if (!plan && run.plan_id) {
      try {
        plan = await getPlan(run.plan_id);
        setPlanCache(plan);
      } catch {
        // Plan fetch failed — include plan_id only
      }
    }
    const blob = {
      plan: plan || { id: run.plan_id, plan_code: run.plan_code },
      run,
      events,
      generated_at: new Date().toISOString(),
    };
    const ok = await copyText(JSON.stringify(blob, null, 2));
    flashCopy(ok ? 'Copied!' : 'Copy failed');
  }

  // Copy single event payload
  async function handleCopyEventPayload(ev: RunEvent) {
    const data = ev.payload ?? {};
    const ok = await copyText(JSON.stringify(data, null, 2));
    flashCopy(ok ? `Copied ${ev.event_type}` : 'Copy failed');
  }

  // Fetch correlated admin logs
  async function handleFetchLogs() {
    if (!run?.correlation_id) return;
    setLogsLoading(true);
    setLogsError(null);
    try {
      const result = await admin.logs(run.correlation_id, {
        since: logsSince,
        limit: logsLimit,
        service: logsService || undefined,
      });
      setLogEntries(result.logs || []);
      setLogsTotal(result.total ?? (result.logs?.length ?? 0));
    } catch (e) {
      setLogsError((e as Error).message);
      setLogEntries([]);
      setLogsTotal(0);
    }
    setLogsLoading(false);
  }

  function truncateMsg(msg: string | undefined, max: number): string {
    if (!msg) return '\u2014';
    return msg.length > max ? msg.slice(0, max) + '\u2026' : msg;
  }

  // Helpers
  function statusColor(status: string): string {
    if (status === 'completed' || status === 'succeeded') return colors.green;
    if (status === 'failed' || status === 'error') return colors.red;
    if (status === 'running' || status === 'in_progress') return colors.blue;
    if (status === 'pending' || status === 'queued') return colors.yellow;
    return colors.textMuted;
  }

  function statusIcon(status: string): string {
    if (status === 'completed' || status === 'succeeded') return '\u2713';
    if (status === 'failed' || status === 'error') return '\u2717';
    if (status === 'running' || status === 'in_progress') return '\u25CB';
    return '\u2022';
  }

  function eventColor(type: string): string {
    if (type.includes('completed') || type.includes('succeeded')) return colors.green;
    if (type.includes('failed') || type.includes('error') || type.includes('timeout')) return colors.red;
    if (type.includes('dispatched') || type.includes('started')) return colors.blue;
    if (type.includes('skipped') || type.includes('cancelled')) return colors.yellow;
    return colors.textMuted;
  }

  function shortId(id: string): string {
    return id && id.length > 12 ? id.slice(0, 8) + '...' : (id || '\u2014');
  }

  function formatDuration(ms?: number): string {
    if (ms == null) return '\u2014';
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    return `${(ms / 60000).toFixed(1)}min`;
  }

  // =========================================================================
  // RENDER
  // =========================================================================

  return (
    <div style={styles.container}>
      {/* Navigation bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '20px' }}>
        <button
          onClick={onBack}
          style={{ ...styles.button, background: 'transparent', border: `1px solid ${colors.border}`, color: colors.text, padding: '6px 14px', fontSize: '12px' }}
        >
          {'\u2190'} Back to Plans
        </button>
        <button
          onClick={() => { didLoadRef.current = false; loadDetail(); }}
          style={{ ...styles.link, fontSize: '13px' }}
        >
          Refresh
        </button>
        {run && (
          <button
            onClick={handleCopyPlanJson}
            style={{ ...styles.button, background: 'transparent', border: `1px solid ${colors.border}`, color: colors.text, padding: '6px 14px', fontSize: '12px' }}
          >
            Copy Plan JSON
          </button>
        )}
        {loading && <span style={{ fontSize: '12px', color: colors.textMuted }}>Loading...</span>}
        {copyStatus && (
          <span style={{ fontSize: '11px', color: colors.green, fontWeight: 500, transition: 'opacity 0.3s' }}>
            {copyStatus}
          </span>
        )}
      </div>

      {error && <div style={styles.error}>{error}</div>}

      {!run && !loading && !error && (
        <div style={{ ...styles.card, padding: '32px', textAlign: 'center', color: colors.textMuted }}>
          Run not found.
        </div>
      )}

      {run && (
        <>
          {/* =============================================================== */}
          {/* HEADER + STATUS                                                 */}
          {/* =============================================================== */}
          <div style={{ ...styles.card, padding: 0 }}>
            <div style={{ padding: '16px 20px', borderBottom: `1px solid ${colors.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ fontSize: '16px', fontWeight: 600 }}>Run Detail</span>
                <span style={{ ...styles.badge, background: `${statusColor(run.status)}20`, color: statusColor(run.status) }}>
                  {statusIcon(run.status)} {run.status}
                </span>
                {run.progress != null && run.status !== 'completed' && run.status !== 'failed' && (
                  <span style={{ ...styles.mono, color: colors.textMuted }}>{run.progress}%</span>
                )}
              </div>
              {run.plan_code && (
                <span style={{ ...styles.badge, background: darkMode ? '#3a3a3c' : '#e8e8ed', color: colors.text, fontSize: '11px' }}>
                  {run.plan_code}
                </span>
              )}
            </div>

            {/* Summary Grid */}
            <div style={{ padding: '16px 20px', borderBottom: `1px solid ${colors.border}`, display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '16px' }}>
              <div>
                <span style={styles.label}>Run ID</span>
                <div style={{ ...styles.mono, background: darkMode ? '#1c1c1e' : '#f0f0f2', padding: '4px 8px', borderRadius: '4px', display: 'inline-block' }}>{shortId(run.id)}</div>
              </div>
              {run.correlation_id && (
                <div>
                  <span style={styles.label}>Correlation ID</span>
                  <div style={{ ...styles.mono, background: darkMode ? '#1c1c1e' : '#f0f0f2', padding: '4px 8px', borderRadius: '4px', display: 'inline-block' }}>{shortId(run.correlation_id)}</div>
                </div>
              )}
              <div>
                <span style={styles.label}>Duration</span>
                <div style={styles.mono}>{formatDuration(run.duration_ms)}</div>
              </div>
              <div>
                <span style={styles.label}>Created</span>
                <div style={{ fontSize: '12px' }}>{new Date(run.created_at).toLocaleString()}</div>
              </div>
              {run.started_at && (
                <div>
                  <span style={styles.label}>Started</span>
                  <div style={{ fontSize: '12px' }}>{new Date(run.started_at).toLocaleString()}</div>
                </div>
              )}
              {run.completed_at && (
                <div>
                  <span style={styles.label}>Completed</span>
                  <div style={{ fontSize: '12px' }}>{new Date(run.completed_at).toLocaleString()}</div>
                </div>
              )}
            </div>

            {/* Progress Bar */}
            {run.progress != null && run.progress > 0 && run.status !== 'completed' && run.status !== 'failed' && (
              <div style={{ padding: '12px 20px', borderBottom: `1px solid ${colors.border}` }}>
                <div style={{ height: '4px', borderRadius: '2px', background: darkMode ? '#3a3a3c' : '#e5e5e5', overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${run.progress}%`, background: colors.blue, borderRadius: '2px', transition: 'width 0.3s ease' }} />
                </div>
              </div>
            )}

            {/* Error */}
            {run.error && (
              <div style={{ padding: '16px 20px', borderBottom: `1px solid ${colors.border}` }}>
                <div style={{ padding: '8px 12px', background: `${colors.red}10`, borderRadius: '6px', fontSize: '13px', color: darkMode ? '#fca5a5' : '#991b1b' }}>
                  <strong>Error:</strong> {run.error}
                </div>
              </div>
            )}
          </div>

          {/* =============================================================== */}
          {/* CONTEXT / INPUTS                                                */}
          {/* =============================================================== */}
          {(run.context || run.inputs) && Object.keys(run.context || run.inputs || {}).length > 0 && (
            <div style={styles.card}>
              <div style={{ padding: '14px 20px' }}>
                <span style={{ ...styles.label, marginBottom: '8px' }}>Context / Inputs</span>
                <pre style={styles.pre}>{JSON.stringify(run.context || run.inputs, null, 2)}</pre>
              </div>
            </div>
          )}

          {/* =============================================================== */}
          {/* RESULT / OUTPUTS                                                */}
          {/* =============================================================== */}
          {(run.result || run.outputs) && Object.keys(run.result || run.outputs || {}).length > 0 && (
            <div style={styles.card}>
              <div style={{ padding: '14px 20px' }}>
                <span style={{ ...styles.label, marginBottom: '8px' }}>Result / Outputs</span>
                <pre style={styles.pre}>{JSON.stringify(run.result || run.outputs, null, 2)}</pre>
              </div>
            </div>
          )}

          {/* =============================================================== */}
          {/* EXECUTION TIMELINE                                              */}
          {/* =============================================================== */}
          <div style={styles.card}>
            <div style={{ padding: '14px 20px', borderBottom: `1px solid ${colors.border}` }}>
              <span style={{ fontSize: '14px', fontWeight: 600 }}>Execution Timeline</span>
              <span style={{ ...styles.mono, color: colors.textMuted, marginLeft: '8px' }}>({events.length} events)</span>
            </div>

            <div style={{ padding: '16px 20px' }}>
              {events.length === 0 ? (
                <div style={{ color: colors.textMuted, fontSize: '12px', textAlign: 'center', padding: '16px' }}>
                  {loading ? 'Loading events...' : 'No events recorded.'}
                </div>
              ) : (
                <div style={{ position: 'relative', paddingLeft: '28px' }}>
                  {/* Vertical connector line */}
                  <div style={{
                    position: 'absolute',
                    left: '9px',
                    top: '6px',
                    bottom: '6px',
                    width: '2px',
                    background: darkMode ? '#3a3a3c' : '#e0e0e0',
                    borderRadius: '1px',
                  }} />

                  {events.map((ev, i) => {
                    const evColor = eventColor(ev.event_type);
                    const isExpanded = expandedEvents.has(ev.id);
                    const hasPayload = !!(ev.payload && JSON.stringify(ev.payload) !== '{}' && JSON.stringify(ev.payload) !== 'null');
                    const hasError = !!(ev.error_code || ev.error_message || ev.error_details);
                    const isLast = i === events.length - 1;

                    return (
                      <div key={ev.id} style={{ position: 'relative', marginBottom: isLast ? 0 : '2px', paddingBottom: isLast ? 0 : '2px' }}>
                        {/* Timeline dot */}
                        <div style={{
                          position: 'absolute',
                          left: '-23px',
                          top: '10px',
                          width: '10px',
                          height: '10px',
                          borderRadius: '50%',
                          background: evColor,
                          border: `2px solid ${colors.cardBg}`,
                          boxShadow: `0 0 0 2px ${evColor}40`,
                          zIndex: 1,
                        }} />

                        {/* Event card */}
                        <div style={{
                          background: darkMode ? '#1c1c1e' : '#ffffff',
                          border: `1px solid ${colors.border}`,
                          borderRadius: '6px',
                          padding: '10px 12px',
                          marginBottom: '8px',
                        }}>
                          {/* Event header row */}
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                            <span style={{
                              ...styles.badge,
                              background: `${evColor}18`,
                              color: evColor,
                              fontSize: '10px',
                              textTransform: 'uppercase',
                              letterSpacing: '0.03em',
                            }}>
                              {ev.event_type}
                            </span>

                            {(ev.step_key || ev.step_id) && (
                              <span style={{
                                ...styles.badge,
                                background: darkMode ? '#3a3a3c' : '#e8e8ed',
                                color: colors.text,
                                fontSize: '10px',
                              }}>
                                {ev.step_key || ev.step_id}
                              </span>
                            )}

                            {ev.capability_identity && (
                              <span style={{ ...styles.mono, fontSize: '10px', color: colors.textMuted }}>
                                {ev.capability_identity}
                              </span>
                            )}

                            <span style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '6px' }}>
                              {hasPayload && (
                                <button
                                  onClick={(e) => { e.stopPropagation(); handleCopyEventPayload(ev); }}
                                  title="Copy payload"
                                  style={{
                                    background: 'transparent',
                                    border: `1px solid ${colors.border}`,
                                    borderRadius: '3px',
                                    padding: '1px 5px',
                                    cursor: 'pointer',
                                    fontSize: '9px',
                                    color: colors.textMuted,
                                    lineHeight: 1,
                                  }}
                                >
                                  Copy
                                </button>
                              )}
                              <span style={{ ...styles.mono, fontSize: '10px', color: colors.textMuted, whiteSpace: 'nowrap' }}>
                                {new Date(ev.event_timestamp || ev.created_at).toLocaleTimeString()}
                                {ev.duration_ms != null && (
                                  <span style={{ marginLeft: '6px', color: evColor }}>{formatDuration(ev.duration_ms)}</span>
                                )}
                              </span>
                            </span>
                          </div>

                          {/* Error inline */}
                          {hasError && (
                            <div style={{ marginTop: '8px', padding: '6px 8px', background: `${colors.red}10`, borderRadius: '4px', fontSize: '11px' }}>
                              {ev.error_code && <span style={{ ...styles.mono, color: colors.red }}>[{ev.error_code}] </span>}
                              <span style={{ color: darkMode ? '#fca5a5' : '#991b1b' }}>{ev.error_message || 'Unknown error'}</span>
                            </div>
                          )}

                          {/* Expand toggle */}
                          {(hasPayload || (hasError && !!ev.error_details)) && (
                            <button
                              onClick={() => toggleExpand(ev.id)}
                              style={{
                                ...styles.link,
                                fontSize: '10px',
                                marginTop: '6px',
                                color: colors.textMuted,
                                display: 'flex',
                                alignItems: 'center',
                                gap: '3px',
                              }}
                            >
                              <span style={{ fontSize: '8px' }}>{isExpanded ? '\u25BC' : '\u25B6'}</span>
                              {isExpanded ? 'Hide' : 'Show'} details
                            </button>
                          )}

                          {/* Expanded payload/error_details */}
                          {isExpanded && (
                            <div style={{ marginTop: '8px' }}>
                              {hasPayload && (
                                <>
                                  <span style={{ ...styles.label, fontSize: '10px', marginBottom: '4px' }}>Payload</span>
                                  <pre style={{ ...styles.pre, maxHeight: '200px', fontSize: '10px' }}>{JSON.stringify(ev.payload, null, 2)}</pre>
                                </>
                              )}
                              {hasError && !!ev.error_details && (
                                <>
                                  <span style={{ ...styles.label, fontSize: '10px', marginBottom: '4px', marginTop: '8px' }}>Error Details</span>
                                  <pre style={{ ...styles.pre, maxHeight: '200px', fontSize: '10px' }}>{JSON.stringify(ev.error_details, null, 2)}</pre>
                                </>
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          {/* =============================================================== */}
          {/* DEBUG PANEL                                                      */}
          {/* =============================================================== */}
          {(() => {
            const lastEv = events.length > 0 ? events[events.length - 1] : null;
            const lastEventType = lastEv?.event_type ?? null;
            const lastEventTime = lastEv ? (lastEv.event_timestamp || lastEv.created_at) : null;

            // Scan all event payloads for task_id / taskId
            let taskId: string | null = null;
            for (const ev of events) {
              if (ev.payload && typeof ev.payload === 'object') {
                const p = ev.payload as Record<string, unknown>;
                const found = p.task_id ?? p.taskId;
                if (found && typeof found === 'string') { taskId = found; break; }
              }
            }

            const lastStepEv = [...events].reverse().find(
              (e) => e.event_type.includes('STEP') || e.event_type.includes('step')
            );

            // Diagnostic hint
            let hint: string | null = null;
            const eventTypes = events.map((e) => e.event_type.toUpperCase());
            const hasStepDispatched = eventTypes.some((t) => t.includes('DISPATCHED'));
            const hasStepCompleted = eventTypes.some((t) => t.includes('STEP') && t.includes('COMPLETED'));
            const hasRunCompleted = eventTypes.some((t) => t.includes('RUN') && t.includes('COMPLETED'));

            if (hasStepDispatched && !hasStepCompleted) {
              hint = 'Runner likely hasn\u2019t completed task. Check Runner tab queue + active runner.';
            } else if (hasStepCompleted && !hasRunCompleted && run.status !== 'completed' && run.status !== 'failed') {
              hint = 'Engine may not have finalized run; refresh events.';
            }

            const debugJson = JSON.stringify({
              runId: run.id,
              status: run.status,
              planId: run.plan_id,
              planCode: run.plan_code,
              lastEvent: lastEv ? { type: lastEv.event_type, time: lastEventTime, id: lastEv.id } : null,
              derived: {
                taskId,
                lastEventType,
                lastEventTime,
                stepId: lastStepEv?.step_id ?? lastStepEv?.step_key ?? null,
                capabilityIdentity: lastStepEv?.capability_identity ?? null,
                targetType: lastStepEv?.target_type ?? null,
              },
              eventCount: events.length,
              generated_at: new Date().toISOString(),
            }, null, 2);

            return (
              <div style={styles.card}>
                <button
                  onClick={() => setDebugOpen((v) => !v)}
                  style={{
                    width: '100%',
                    padding: '12px 20px',
                    background: 'transparent',
                    border: 'none',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    color: colors.textMuted,
                    fontSize: '12px',
                    fontWeight: 600,
                    textAlign: 'left',
                  }}
                >
                  <span style={{ fontSize: '9px' }}>{debugOpen ? '\u25BC' : '\u25B6'}</span>
                  Debug
                  {hint && <span style={{ fontWeight: 400, fontSize: '11px', color: colors.yellow, marginLeft: '4px' }}>{'\u26A0'}</span>}
                </button>

                {debugOpen && (
                  <div style={{ padding: '0 20px 16px' }}>
                    <table style={{ width: '100%', fontSize: '11px', borderCollapse: 'collapse' }}>
                      <tbody>
                        {[
                          ['Last Event', lastEventType ?? '\u2014'],
                          ['Last Event Time', lastEventTime ? new Date(lastEventTime).toLocaleString() : '\u2014'],
                          ['Task ID', taskId ?? 'not found in payloads'],
                          ['Step', lastStepEv ? (lastStepEv.step_key || lastStepEv.step_id || '\u2014') : '\u2014'],
                          ['Capability', lastStepEv?.capability_identity ?? '\u2014'],
                          ['Target Type', lastStepEv?.target_type ?? '\u2014'],
                          ['Event Count', String(events.length)],
                        ].map(([label, value]) => (
                          <tr key={label}>
                            <td style={{ padding: '3px 8px 3px 0', color: colors.textMuted, whiteSpace: 'nowrap', verticalAlign: 'top' }}>{label}</td>
                            <td style={{ padding: '3px 0', fontFamily: 'SF Mono, Menlo, monospace', fontSize: '11px', wordBreak: 'break-all' }}>{value}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>

                    {hint && (
                      <div style={{
                        marginTop: '10px',
                        padding: '8px 12px',
                        background: `${colors.yellow}12`,
                        border: `1px solid ${colors.yellow}30`,
                        borderRadius: '6px',
                        fontSize: '11px',
                        color: darkMode ? '#ffd60a' : '#92400e',
                      }}>
                        {hint}
                      </div>
                    )}

                    <button
                      onClick={async () => {
                        const ok = await copyText(debugJson);
                        flashCopy(ok ? 'Copied debug JSON' : 'Copy failed');
                      }}
                      style={{
                        marginTop: '10px',
                        ...styles.button,
                        padding: '5px 14px',
                        fontSize: '11px',
                        background: 'transparent',
                        border: `1px solid ${colors.border}`,
                        color: colors.text,
                      }}
                    >
                      Copy Debug JSON
                    </button>
                  </div>
                )}
              </div>
            );
          })()}

          {/* =============================================================== */}
          {/* LOGS SECTION                                                     */}
          {/* =============================================================== */}
          <div style={styles.card}>
            <button
              onClick={() => setLogsOpen((v) => !v)}
              style={{
                width: '100%',
                padding: '12px 20px',
                background: 'transparent',
                border: 'none',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                color: colors.textMuted,
                fontSize: '12px',
                fontWeight: 600,
                textAlign: 'left',
              }}
            >
              <span style={{ fontSize: '9px' }}>{logsOpen ? '\u25BC' : '\u25B6'}</span>
              Logs
              {logEntries.length > 0 && (
                <span style={{ ...styles.mono, fontWeight: 400, color: colors.textMuted }}>({logsTotal})</span>
              )}
            </button>

            {logsOpen && (
              <div style={{ padding: '0 20px 16px' }}>
                {/* No correlation_id warning */}
                {!run.correlation_id ? (
                  <div style={{
                    padding: '10px 14px',
                    background: `${colors.yellow}12`,
                    border: `1px solid ${colors.yellow}30`,
                    borderRadius: '6px',
                    fontSize: '12px',
                    color: darkMode ? '#ffd60a' : '#92400e',
                  }}>
                    No correlation_id available on this run.
                  </div>
                ) : (
                  <>
                    {/* Filter controls */}
                    <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap', marginBottom: '12px' }}>
                      <label style={{ fontSize: '11px', color: colors.textMuted }}>
                        Since{' '}
                        <select
                          value={logsSince}
                          onChange={(e) => setLogsSince(e.target.value)}
                          style={{
                            fontSize: '11px',
                            padding: '3px 6px',
                            borderRadius: '4px',
                            border: `1px solid ${colors.border}`,
                            background: darkMode ? '#1c1c1e' : '#fff',
                            color: colors.text,
                          }}
                        >
                          <option value="10m">10m</option>
                          <option value="1h">1h</option>
                          <option value="24h">24h</option>
                        </select>
                      </label>

                      <label style={{ fontSize: '11px', color: colors.textMuted }}>
                        Service{' '}
                        <input
                          type="text"
                          value={logsService}
                          onChange={(e) => setLogsService(e.target.value)}
                          placeholder="optional"
                          style={{
                            fontSize: '11px',
                            padding: '3px 6px',
                            borderRadius: '4px',
                            border: `1px solid ${colors.border}`,
                            background: darkMode ? '#1c1c1e' : '#fff',
                            color: colors.text,
                            width: '100px',
                          }}
                        />
                      </label>

                      <label style={{ fontSize: '11px', color: colors.textMuted }}>
                        Limit{' '}
                        <input
                          type="number"
                          value={logsLimit}
                          onChange={(e) => setLogsLimit(Math.min(1000, Math.max(1, Number(e.target.value) || 200)))}
                          style={{
                            fontSize: '11px',
                            padding: '3px 6px',
                            borderRadius: '4px',
                            border: `1px solid ${colors.border}`,
                            background: darkMode ? '#1c1c1e' : '#fff',
                            color: colors.text,
                            width: '60px',
                          }}
                        />
                      </label>

                      <button
                        onClick={handleFetchLogs}
                        disabled={logsLoading}
                        style={{
                          ...styles.button,
                          padding: '4px 14px',
                          fontSize: '11px',
                          background: colors.blue,
                          color: '#fff',
                          opacity: logsLoading ? 0.6 : 1,
                        }}
                      >
                        {logsLoading ? 'Fetching...' : 'Fetch Logs'}
                      </button>

                      {logEntries.length > 0 && (
                        <button
                          onClick={async () => {
                            const ok = await copyText(JSON.stringify(logEntries, null, 2));
                            flashCopy(ok ? 'Copied logs JSON' : 'Copy failed');
                          }}
                          style={{
                            ...styles.button,
                            padding: '4px 14px',
                            fontSize: '11px',
                            background: 'transparent',
                            border: `1px solid ${colors.border}`,
                            color: colors.text,
                          }}
                        >
                          Copy Logs JSON
                        </button>
                      )}
                    </div>

                    {/* Error */}
                    {logsError && (
                      <div style={{ ...styles.error, marginBottom: '10px' }}>{logsError}</div>
                    )}

                    {/* Log table */}
                    {logEntries.length > 0 && (
                      <div style={{ overflow: 'auto', maxHeight: '400px' }}>
                        <table style={{ width: '100%', fontSize: '10px', borderCollapse: 'collapse', fontFamily: 'SF Mono, Menlo, monospace' }}>
                          <thead>
                            <tr style={{ borderBottom: `1px solid ${colors.border}` }}>
                              {['Time', 'Level', 'Component', 'Op', 'Path', 'Status', 'Message'].map((h) => (
                                <th
                                  key={h}
                                  style={{
                                    padding: '4px 6px',
                                    textAlign: 'left',
                                    color: colors.textMuted,
                                    fontWeight: 600,
                                    fontSize: '9px',
                                    textTransform: 'uppercase',
                                    letterSpacing: '0.03em',
                                    whiteSpace: 'nowrap',
                                    position: 'sticky',
                                    top: 0,
                                    background: colors.cardBg,
                                  }}
                                >
                                  {h}
                                </th>
                              ))}
                            </tr>
                          </thead>
                          <tbody>
                            {logEntries.map((log, i) => {
                              const lvl = (log.level || '').toUpperCase();
                              const lvlColor = lvl === 'ERROR' ? colors.red : lvl === 'WARN' ? colors.yellow : colors.textMuted;
                              return (
                                <tr
                                  key={i}
                                  style={{ borderBottom: `1px solid ${colors.border}22` }}
                                  title={log.message || ''}
                                >
                                  <td style={{ padding: '3px 6px', whiteSpace: 'nowrap' }}>
                                    {log.ts ? new Date(log.ts).toLocaleTimeString() : '\u2014'}
                                  </td>
                                  <td style={{ padding: '3px 6px', color: lvlColor, fontWeight: 500 }}>{lvl || '\u2014'}</td>
                                  <td style={{ padding: '3px 6px' }}>{log.component || '\u2014'}</td>
                                  <td style={{ padding: '3px 6px' }}>{log.op || '\u2014'}</td>
                                  <td style={{ padding: '3px 6px', maxWidth: '120px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                    {log.path || '\u2014'}
                                  </td>
                                  <td style={{ padding: '3px 6px' }}>{log.status != null ? String(log.status) : '\u2014'}</td>
                                  <td style={{ padding: '3px 6px', maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                    {truncateMsg(log.message, 160)}
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    )}

                    {/* Empty state after fetch */}
                    {!logsLoading && !logsError && logEntries.length === 0 && logsTotal === 0 && (
                      <div style={{ color: colors.textMuted, fontSize: '11px', textAlign: 'center', padding: '12px' }}>
                        Click "Fetch Logs" to load correlated logs.
                      </div>
                    )}
                  </>
                )}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
