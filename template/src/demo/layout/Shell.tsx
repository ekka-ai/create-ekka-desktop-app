/**
 * Application Shell
 * Main layout with sidebar navigation and content area
 * Supports light/dark mode
 */

import { CSSProperties, ReactNode } from 'react';
import { Sidebar, Page } from './Sidebar';

interface ShellProps {
  selectedPage: Page;
  onNavigate: (page: Page) => void;
  children: ReactNode;
  darkMode: boolean;
  onToggleDarkMode: () => void;
}

export function Shell({ selectedPage, onNavigate, children, darkMode, onToggleDarkMode }: ShellProps) {
  const styles: Record<string, CSSProperties> = {
    shell: {
      display: 'flex',
      height: '100vh',
      width: '100vw',
      overflow: 'hidden',
      background: darkMode ? '#1c1c1e' : '#ffffff',
      fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Text", system-ui, sans-serif',
    },
    main: {
      flex: 1,
      overflow: 'auto',
      background: darkMode ? '#1c1c1e' : '#ffffff',
      position: 'relative',
    },
    header: {
      position: 'absolute',
      top: '16px',
      right: '24px',
      zIndex: 10,
    },
    toggleButton: {
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      width: '36px',
      height: '36px',
      background: darkMode ? '#2c2c2e' : '#f5f5f7',
      border: `1px solid ${darkMode ? '#3a3a3c' : '#e5e5e5'}`,
      borderRadius: '8px',
      cursor: 'pointer',
      color: darkMode ? '#ffffff' : '#1d1d1f',
      transition: 'background 0.15s ease',
    },
    content: {
      padding: '32px 40px',
      maxWidth: '720px',
    },
  };

  return (
    <div style={styles.shell}>
      <Sidebar selectedPage={selectedPage} onNavigate={onNavigate} darkMode={darkMode} />
      <main style={styles.main}>
        <div style={styles.header}>
          <button
            onClick={onToggleDarkMode}
            style={styles.toggleButton}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = darkMode ? '#3a3a3c' : '#e5e5e5';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = darkMode ? '#2c2c2e' : '#f5f5f7';
            }}
            title={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {darkMode ? <SunIcon /> : <MoonIcon />}
          </button>
        </div>
        <div style={styles.content}>
          {children}
        </div>
      </main>
    </div>
  );
}

function SunIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="5" />
      <line x1="12" y1="1" x2="12" y2="3" />
      <line x1="12" y1="21" x2="12" y2="23" />
      <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
      <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
      <line x1="1" y1="12" x2="3" y2="12" />
      <line x1="21" y1="12" x2="23" y2="12" />
      <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
      <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
    </svg>
  );
}
