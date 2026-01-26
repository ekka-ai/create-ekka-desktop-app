/**
 * Sidebar Navigation
 * Professional admin-style left navigation with Settings at bottom
 * Supports light/dark mode
 */

import { CSSProperties } from 'react';

export type Page = 'stateful-data' | 'async-work' | 'settings';

interface NavItem {
  id: string;
  label: string;
  disabled?: boolean;
}

interface SidebarProps {
  selectedPage: Page;
  onNavigate: (page: Page) => void;
  darkMode: boolean;
}

const demoItems: NavItem[] = [
  { id: 'stateful-data', label: 'Stateful Data' },
  { id: 'async-work', label: 'Asynchronous Work' },
];

const futureItems: NavItem[] = [
  { id: 'execution', label: 'Execution', disabled: true },
  { id: 'policies', label: 'Policies', disabled: true },
  { id: 'audit', label: 'Audit', disabled: true },
];

export function Sidebar({ selectedPage, onNavigate, darkMode }: SidebarProps) {
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
      display: 'block',
      width: '100%',
      padding: '8px 10px',
      margin: '1px 0',
      background: 'transparent',
      border: 'none',
      borderRadius: '6px',
      fontSize: '13px',
      fontWeight: 400,
      color: colors.text,
      textAlign: 'left',
      cursor: 'pointer',
      transition: 'background 0.15s ease',
    },
    navItemActive: {
      background: colors.active,
      fontWeight: 500,
    },
    navItemDisabled: {
      color: colors.textMuted,
      cursor: 'default',
    },
    comingSoon: {
      fontSize: '10px',
      color: colors.textMuted,
      marginLeft: '6px',
      fontWeight: 400,
    },
    bottomSection: {
      padding: '8px',
      borderTop: `1px solid ${colors.border}`,
    },
    settingsItem: {
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      width: '100%',
      padding: '8px 10px',
      background: 'transparent',
      border: 'none',
      borderRadius: '6px',
      fontSize: '13px',
      fontWeight: 400,
      color: colors.text,
      textAlign: 'left',
      cursor: 'pointer',
      transition: 'background 0.15s ease',
    },
  };

  const renderNavItem = (item: NavItem) => {
    const isActive = selectedPage === item.id;
    const isDisabled = item.disabled;

    return (
      <button
        key={item.id}
        onClick={() => !isDisabled && onNavigate(item.id as Page)}
        style={{
          ...styles.navItem,
          ...(isActive ? styles.navItemActive : {}),
          ...(isDisabled ? styles.navItemDisabled : {}),
        }}
        onMouseEnter={(e) => {
          if (!isDisabled && !isActive) {
            e.currentTarget.style.background = colors.hover;
          }
        }}
        onMouseLeave={(e) => {
          if (!isActive) {
            e.currentTarget.style.background = 'transparent';
          }
        }}
        disabled={isDisabled}
      >
        {item.label}
        {isDisabled && <span style={styles.comingSoon}>Soon</span>}
      </button>
    );
  };

  const isSettingsActive = selectedPage === 'settings';

  return (
    <aside style={styles.sidebar}>
      <div style={styles.logo}>
        <span style={styles.logoText}>EKKA Desktop</span>
      </div>

      <nav style={styles.nav}>
        <div style={styles.sectionLabel}>Demo</div>
        {demoItems.map(renderNavItem)}

        <div style={{ ...styles.sectionLabel, marginTop: '16px' }}>Coming Soon</div>
        {futureItems.map(renderNavItem)}
      </nav>

      <div style={styles.bottomSection}>
        <button
          onClick={() => onNavigate('settings')}
          style={{
            ...styles.settingsItem,
            ...(isSettingsActive ? styles.navItemActive : {}),
          }}
          onMouseEnter={(e) => {
            if (!isSettingsActive) {
              e.currentTarget.style.background = colors.hover;
            }
          }}
          onMouseLeave={(e) => {
            if (!isSettingsActive) {
              e.currentTarget.style.background = 'transparent';
            }
          }}
        >
          <SettingsIcon />
          Settings
        </button>
      </div>
    </aside>
  );
}

function SettingsIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" style={{ opacity: 0.7 }}>
      <path
        d="M8 4.754a3.246 3.246 0 1 0 0 6.492 3.246 3.246 0 0 0 0-6.492zM6.754 8a1.246 1.246 0 1 1 2.492 0 1.246 1.246 0 0 1-2.492 0z"
        fill="currentColor"
      />
      <path
        d="M9.796 1.343c-.527-1.79-3.065-1.79-3.592 0l-.094.319a.873.873 0 0 1-1.255.52l-.292-.16c-1.64-.892-3.433.902-2.54 2.541l.159.292a.873.873 0 0 1-.52 1.255l-.319.094c-1.79.527-1.79 3.065 0 3.592l.319.094a.873.873 0 0 1 .52 1.255l-.16.292c-.892 1.64.901 3.434 2.541 2.54l.292-.159a.873.873 0 0 1 1.255.52l.094.319c.527 1.79 3.065 1.79 3.592 0l.094-.319a.873.873 0 0 1 1.255-.52l.292.16c1.64.893 3.434-.902 2.54-2.541l-.159-.292a.873.873 0 0 1 .52-1.255l.319-.094c1.79-.527 1.79-3.065 0-3.592l-.319-.094a.873.873 0 0 1-.52-1.255l.16-.292c.893-1.64-.902-3.433-2.541-2.54l-.292.159a.873.873 0 0 1-1.255-.52l-.094-.319zm-2.633.283c.246-.835 1.428-.835 1.674 0l.094.319a1.873 1.873 0 0 0 2.693 1.115l.291-.16c.764-.415 1.6.42 1.184 1.185l-.159.292a1.873 1.873 0 0 0 1.116 2.692l.318.094c.835.246.835 1.428 0 1.674l-.319.094a1.873 1.873 0 0 0-1.115 2.693l.16.291c.415.764-.421 1.6-1.185 1.184l-.291-.159a1.873 1.873 0 0 0-2.693 1.116l-.094.318c-.246.835-1.428.835-1.674 0l-.094-.319a1.873 1.873 0 0 0-2.692-1.115l-.292.16c-.764.415-1.6-.421-1.184-1.185l.159-.291a1.873 1.873 0 0 0-1.116-2.693l-.318-.094c-.835-.246-.835-1.428 0-1.674l.319-.094a1.873 1.873 0 0 0 1.115-2.692l-.16-.292c-.415-.764.421-1.6 1.185-1.184l.292.159a1.873 1.873 0 0 0 2.692-1.116l.094-.318z"
        fill="currentColor"
      />
    </svg>
  );
}
