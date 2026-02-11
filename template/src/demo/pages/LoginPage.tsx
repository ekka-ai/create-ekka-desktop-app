/**
 * Login Page
 *
 * Simple email/password authentication form.
 */

import { useState, type ReactElement, type FormEvent } from 'react';
import { ekka } from '../../ekka';

interface LoginPageProps {
  onLoginSuccess: () => void;
  darkMode: boolean;
}

export function LoginPage({ onLoginSuccess, darkMode }: LoginPageProps): ReactElement {
  const [email, setEmail] = useState(import.meta.env.VITE_DEV_EMAIL || '');
  const [password, setPassword] = useState(import.meta.env.VITE_DEV_PASSWORD || '');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const colors = {
    bg: darkMode ? '#1c1c1e' : '#ffffff',
    cardBg: darkMode ? '#2c2c2e' : '#f5f5f7',
    border: darkMode ? '#3a3a3c' : '#e5e5e5',
    text: darkMode ? '#ffffff' : '#1d1d1f',
    textMuted: darkMode ? '#98989d' : '#86868b',
    inputBg: darkMode ? '#1c1c1e' : '#ffffff',
    buttonBg: '#007aff',
    buttonHover: '#0066d6',
    errorBg: darkMode ? '#3c1618' : '#fef2f2',
    errorBorder: darkMode ? '#7f1d1d' : '#fecaca',
    errorText: darkMode ? '#fca5a5' : '#991b1b',
  };

  const styles: Record<string, React.CSSProperties> = {
    container: {
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      minHeight: '100vh',
      background: colors.bg,
      fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Text", system-ui, sans-serif',
    },
    card: {
      width: '100%',
      maxWidth: '360px',
      padding: '32px',
      background: colors.cardBg,
      borderRadius: '12px',
      border: `1px solid ${colors.border}`,
    },
    logo: {
      fontSize: '20px',
      fontWeight: 600,
      color: colors.text,
      textAlign: 'center',
      marginBottom: '8px',
    },
    subtitle: {
      fontSize: '13px',
      color: colors.textMuted,
      textAlign: 'center',
      marginBottom: '24px',
    },
    form: {
      display: 'flex',
      flexDirection: 'column',
      gap: '16px',
    },
    inputGroup: {
      display: 'flex',
      flexDirection: 'column',
      gap: '6px',
    },
    label: {
      fontSize: '13px',
      fontWeight: 500,
      color: colors.text,
    },
    input: {
      padding: '10px 12px',
      fontSize: '14px',
      border: `1px solid ${colors.border}`,
      borderRadius: '8px',
      background: colors.inputBg,
      color: colors.text,
      outline: 'none',
      transition: 'border-color 0.15s ease',
    },
    button: {
      marginTop: '8px',
      padding: '12px 16px',
      fontSize: '14px',
      fontWeight: 500,
      color: '#ffffff',
      background: colors.buttonBg,
      border: 'none',
      borderRadius: '8px',
      cursor: 'pointer',
      transition: 'background 0.15s ease',
    },
    buttonDisabled: {
      background: colors.textMuted,
      cursor: 'not-allowed',
    },
    error: {
      padding: '10px 12px',
      fontSize: '13px',
      color: colors.errorText,
      background: colors.errorBg,
      border: `1px solid ${colors.errorBorder}`,
      borderRadius: '8px',
    },
  };

  async function handleSubmit(e: FormEvent): Promise<void> {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await ekka.auth.login(email, password);
      onLoginSuccess();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Login failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  }

  const isValid = email.trim() !== '' && password !== '';

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <div style={styles.logo}>{__APP_NAME__}</div>
        <div style={styles.subtitle}>Sign in to continue</div>

        <form style={styles.form} onSubmit={handleSubmit}>
          {error && <div style={styles.error}>{error}</div>}

          <div style={styles.inputGroup}>
            <label style={styles.label}>Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              style={styles.input}
              autoFocus
              disabled={loading}
            />
          </div>

          <div style={styles.inputGroup}>
            <label style={styles.label}>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter your password"
              style={styles.input}
              disabled={loading}
            />
          </div>

          <button
            type="submit"
            style={{
              ...styles.button,
              ...(!isValid || loading ? styles.buttonDisabled : {}),
            }}
            disabled={!isValid || loading}
            onMouseEnter={(e) => {
              if (isValid && !loading) {
                e.currentTarget.style.background = colors.buttonHover;
              }
            }}
            onMouseLeave={(e) => {
              if (isValid && !loading) {
                e.currentTarget.style.background = colors.buttonBg;
              }
            }}
          >
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  );
}
