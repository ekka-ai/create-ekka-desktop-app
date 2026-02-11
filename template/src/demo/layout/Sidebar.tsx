/**
 * Sidebar Navigation
 * Clean admin-style left navigation
 */

import { type CSSProperties, type ReactElement } from 'react';

export type Page = 'audit-log' | 'path-permissions' | 'vault' | 'runner' | 'execution-plans' | 'system';

interface SidebarProps {
  selectedPage: Page;
  onNavigate: (page: Page) => void;
  darkMode: boolean;
}

export function Sidebar({ selectedPage, onNavigate, darkMode }: SidebarProps): ReactElement {
  const colors = {
    bg: darkMode ? '#2c2c2e' : '#f5f5f7',
    border: darkMode ? '#3a3a3c' : '#e5e5e5',
    text: darkMode ? '#ffffff' : '#1d1d1f',
    textMuted: darkMode ? '#98989d' : '#86868b',
    hover: darkMode ? 'rgba(255, 255, 255, 0.06)' : 'rgba(0, 0, 0, 0.04)',
    active: darkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.08)',
  };

  const styles: Record<string, CSSProperties> = {
    sidebar: {
      width: '220px',
      minWidth: '220px',
      height: '100vh',
      background: colors.bg,
      borderRight: `1px solid ${colors.border}`,
      display: 'flex',
      flexDirection: 'column',
      fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Text", system-ui, sans-serif',
    },
    logo: {
      padding: '20px 16px 16px',
      borderBottom: `1px solid ${colors.border}`,
    },
    logoText: {
      fontSize: '14px',
      fontWeight: 600,
      color: colors.text,
      letterSpacing: '-0.01em',
    },
    nav: {
      flex: 1,
      padding: '12px 8px',
      overflowY: 'auto',
    },
    sectionLabel: {
      fontSize: '11px',
      fontWeight: 600,
      color: colors.textMuted,
      textTransform: 'uppercase',
      letterSpacing: '0.04em',
      padding: '12px 10px 6px',
      marginTop: '4px',
    },
    navItem: {
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      width: '100%',
      padding: '8px 10px',
      margin: '1px 0',
      background: 'transparent',
      border: 'none',
      borderRadius: '6px',
      fontSize: '13px',
      fontWeight: 400,
      color: colors.text,
      textAlign: 'left' as const,
      cursor: 'pointer',
      transition: 'background 0.15s ease',
    },
    navItemActive: {
      background: colors.active,
      fontWeight: 500,
    },
    bottomSection: {
      padding: '8px',
      borderTop: `1px solid ${colors.border}`,
    },
  };

  const NavButton = ({
    page,
    label,
    icon,
  }: {
    page: Page;
    label: string;
    icon: ReactElement;
  }) => {
    const isActive = selectedPage === page;
    return (
      <button
        onClick={() => onNavigate(page)}
        style={{
          ...styles.navItem,
          ...(isActive ? styles.navItemActive : {}),
        }}
        onMouseEnter={(e) => {
          if (!isActive) e.currentTarget.style.background = colors.hover;
        }}
        onMouseLeave={(e) => {
          if (!isActive) e.currentTarget.style.background = 'transparent';
        }}
      >
        {icon}
        {label}
      </button>
    );
  };

  return (
    <aside style={styles.sidebar}>
      <div style={styles.logo}>
        <span style={styles.logoText}>{__APP_NAME__}</span>
      </div>

      <nav style={styles.nav}>
        <div style={styles.sectionLabel}>Tools</div>
        <NavButton page="path-permissions" label="Path Permissions" icon={<PathIcon />} />
        <NavButton page="vault" label="Vault" icon={<VaultIcon />} />
        <NavButton page="runner" label="Runner" icon={<RunnerIcon />} />
        <NavButton page="execution-plans" label="Execution Plans" icon={<ExecutionIcon />} />
        <NavButton page="audit-log" label="Audit Log" icon={<AuditIcon />} />
      </nav>

      <div style={styles.bottomSection}>
        <NavButton page="system" label="System" icon={<SystemIcon />} />
      </div>
    </aside>
  );
}

function PathIcon(): ReactElement {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" style={{ opacity: 0.7 }}>
      <path d="M1 3.5A1.5 1.5 0 0 1 2.5 2h2.764c.958 0 1.764.382 2.236 1l.472.707c.188.282.51.543 1.028.543h4.5A1.5 1.5 0 0 1 15 5.75v6.75A1.5 1.5 0 0 1 13.5 14h-11A1.5 1.5 0 0 1 1 12.5v-9zm1.5-.5a.5.5 0 0 0-.5.5v9a.5.5 0 0 0 .5.5h11a.5.5 0 0 0 .5-.5V5.75a.5.5 0 0 0-.5-.5H9a2.016 2.016 0 0 1-1.528-.793l-.472-.707C6.764 3.393 6.366 3 5.264 3H2.5z" />
    </svg>
  );
}

function AuditIcon(): ReactElement {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" style={{ opacity: 0.7 }}>
      <path d="M2.5 2a.5.5 0 0 0-.5.5v11a.5.5 0 0 0 .5.5h11a.5.5 0 0 0 .5-.5v-11a.5.5 0 0 0-.5-.5h-11zm0-1h11A1.5 1.5 0 0 1 15 2.5v11a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 1 13.5v-11A1.5 1.5 0 0 1 2.5 1z" />
      <path d="M4 4.5a.5.5 0 0 1 .5-.5h7a.5.5 0 0 1 0 1h-7a.5.5 0 0 1-.5-.5zm0 3a.5.5 0 0 1 .5-.5h7a.5.5 0 0 1 0 1h-7a.5.5 0 0 1-.5-.5zm0 3a.5.5 0 0 1 .5-.5h4a.5.5 0 0 1 0 1h-4a.5.5 0 0 1-.5-.5z" />
    </svg>
  );
}

function VaultIcon(): ReactElement {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" style={{ opacity: 0.7 }}>
      <path d="M4 4a3 3 0 0 1 3-3h2a3 3 0 0 1 3 3v1h1a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h1V4zm3-2a2 2 0 0 0-2 2v1h6V4a2 2 0 0 0-2-2H7zM3 6a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1V7a1 1 0 0 0-1-1H3z" />
      <path d="M8 9a1 1 0 0 0-1 1v1a1 1 0 1 0 2 0v-1a1 1 0 0 0-1-1z" />
    </svg>
  );
}

function SystemIcon(): ReactElement {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" style={{ opacity: 0.7 }}>
      <path d="M8 0L1 3v5c0 4.5 3 7.5 7 9 4-1.5 7-4.5 7-9V3L8 0zm0 1.2L14 3.7v4.8c0 3.8-2.5 6.3-6 7.7-3.5-1.4-6-3.9-6-7.7V3.7L8 1.2z" />
      <path d="M6.5 7.5L5 9l2 2 4-4-1.5-1.5L7 8l-.5-.5z" />
    </svg>
  );
}

function RunnerIcon(): ReactElement {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" style={{ opacity: 0.7 }}>
      <path d="M8 3a5 5 0 1 0 4.546 2.914.5.5 0 0 1 .908-.417A6 6 0 1 1 8 2v1z" />
      <path d="M8 4.466V.534a.25.25 0 0 1 .41-.192l2.36 1.966c.12.1.12.284 0 .384L8.41 4.658A.25.25 0 0 1 8 4.466z" />
      <path d="M8 8a.5.5 0 1 1 0-1 .5.5 0 0 1 0 1z" />
    </svg>
  );
}

function ExecutionIcon(): ReactElement {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" style={{ opacity: 0.7 }}>
      <path d="M6 3.5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5zm0 4a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5zm0 4a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5z" />
      <path d="M2.5 3l2 1.5L2.5 6V3zm0 4l2 1.5L2.5 10V7zm0 4l2 1.5-2 1.5V11z" />
    </svg>
  );
}
