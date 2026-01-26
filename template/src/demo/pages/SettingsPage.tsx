/**
 * Settings Page
 * Runtime diagnostics with dark mode support
 */

import { useState, useEffect, type CSSProperties, type ReactElement } from 'react';
import { ekka, type RuntimeInfo } from '../../ekka';

interface SettingsPageProps {
  darkMode: boolean;
}

export function SettingsPage({ darkMode }: SettingsPageProps): ReactElement {
  const [info, setInfo] = useState<RuntimeInfo>({
    runtime: 'web',
    engine_present: false,
  });
  const [mode, setMode] = useState<string>('demo');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    void detect();
  }, []);

  async function detect(): Promise<void> {
    try {
      const runtimeInfo = await ekka.runtime.refresh();
      setInfo(runtimeInfo);
      setMode(ekka.runtime.mode());
    } catch {
      setInfo({
        runtime: 'web',
        engine_present: false,
      });
      setMode('demo');
    }
    setLoading(false);
  }

  const colors = {
    text: darkMode ? '#ffffff' : '#1d1d1f',
    textMuted: darkMode ? '#98989d' : '#6e6e73',
    bg: darkMode ? '#2c2c2e' : '#fafafa',
    border: darkMode ? '#3a3a3c' : '#e5e5e5',
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
      overflow: 'hidden',
    },
    row: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      padding: '14px 16px',
      borderBottom: `1px solid ${colors.border}`,
    },
    rowLast: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      padding: '14px 16px',
    },
    label: {
      fontSize: '13px',
      color: colors.text,
      fontWeight: 400,
    },
    badge: {
      display: 'inline-flex',
      alignItems: 'center',
      padding: '4px 10px',
      borderRadius: '4px',
      fontSize: '12px',
      fontWeight: 500,
    },
    badgeBlue: {
      background: darkMode ? '#1e3a5f' : '#e0f2fe',
      color: darkMode ? '#60a5fa' : '#0369a1',
    },
    badgeAmber: {
      background: darkMode ? '#422006' : '#fef3c7',
      color: darkMode ? '#fbbf24' : '#92400e',
    },
    badgeGreen: {
      background: darkMode ? '#14532d' : '#dcfce7',
      color: darkMode ? '#4ade80' : '#166534',
    },
    badgeGray: {
      background: darkMode ? '#374151' : '#f3f4f6',
      color: darkMode ? '#9ca3af' : '#6b7280',
    },
    badgePurple: {
      background: darkMode ? '#3b0764' : '#f3e8ff',
      color: darkMode ? '#c084fc' : '#7c3aed',
    },
    loadingText: {
      padding: '20px 16px',
      fontSize: '13px',
      color: colors.textMuted,
    },
  };

  const isDesktop = info.runtime === 'tauri';

  if (loading) {
    return (
      <div>
        <header style={styles.header}>
          <h1 style={styles.title}>Settings</h1>
          <p style={styles.description}>Runtime diagnostics and configuration.</p>
        </header>
        <div style={styles.card}>
          <p style={styles.loadingText}>Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div>
      <header style={styles.header}>
        <h1 style={styles.title}>Settings</h1>
        <p style={styles.description}>Runtime diagnostics and configuration.</p>
      </header>

      <div style={styles.card}>
        <div style={styles.row}>
          <span style={styles.label}>Runtime</span>
          <span style={{ ...styles.badge, ...(isDesktop ? styles.badgeBlue : styles.badgeAmber) }}>
            {isDesktop ? 'Desktop (Tauri)' : 'Web (Browser)'}
          </span>
        </div>

        <div style={styles.row}>
          <span style={styles.label}>Engine</span>
          <span style={{ ...styles.badge, ...(info.engine_present ? styles.badgeGreen : styles.badgeGray) }}>
            {info.engine_present ? 'Present' : 'Not present'}
          </span>
        </div>

        <div style={styles.rowLast}>
          <span style={styles.label}>Mode</span>
          <span style={{ ...styles.badge, ...(mode === 'engine' ? styles.badgePurple : styles.badgeGray) }}>
            {mode === 'engine' ? 'Engine' : 'Demo'}
          </span>
        </div>
      </div>
    </div>
  );
}
