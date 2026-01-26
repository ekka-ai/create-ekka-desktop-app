/**
 * EKKA Desktop App ESLint Configuration
 *
 * GUARDRAILS ENFORCED:
 * - No fs, https, axios, child_process imports (TS is sandboxed)
 * - No process.env access (TS MUST NOT decide config)
 * - No direct fetch() calls outside src/ekka/client.ts
 * - All network MUST go through the ekka client
 *
 * These rules enforce the EKKA security model:
 * TS communicates ONLY through the ekka client to EKKA's servers.
 */

import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist', 'node_modules', 'src-tauri', 'vite.config.ts', 'eslint.config.js']),

  // Base config for all TypeScript files
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactRefresh.configs.vite,
    ],
    plugins: {
      'react-hooks': reactHooks,
    },
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
    rules: {
      // React hooks rules
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',

      // ========================================
      // EKKA GUARDRAILS - FORBIDDEN IMPORTS
      // ========================================
      'no-restricted-imports': ['error', {
        paths: [
          // Node.js modules - TS MUST NOT access filesystem or spawn processes
          { name: 'fs', message: 'EKKA: TS is sandboxed. TS MUST NOT read files.' },
          { name: 'fs/promises', message: 'EKKA: TS is sandboxed. TS MUST NOT read files.' },
          { name: 'node:fs', message: 'EKKA: TS is sandboxed. TS MUST NOT read files.' },
          { name: 'node:fs/promises', message: 'EKKA: TS is sandboxed. TS MUST NOT read files.' },
          { name: 'path', message: 'EKKA: TS is sandboxed. Use ekka client for all operations.' },
          { name: 'node:path', message: 'EKKA: TS is sandboxed. Use ekka client for all operations.' },
          { name: 'child_process', message: 'EKKA: TS is sandboxed. TS MUST NOT spawn processes.' },
          { name: 'node:child_process', message: 'EKKA: TS is sandboxed. TS MUST NOT spawn processes.' },

          // Network libraries - TS MUST NOT make direct network calls
          { name: 'https', message: 'EKKA: TS MUST NOT make direct network calls. Use ekka client only.' },
          { name: 'node:https', message: 'EKKA: TS MUST NOT make direct network calls. Use ekka client only.' },
          { name: 'http', message: 'EKKA: TS MUST NOT make direct network calls. Use ekka client only.' },
          { name: 'node:http', message: 'EKKA: TS MUST NOT make direct network calls. Use ekka client only.' },
          { name: 'axios', message: 'EKKA: TS MUST NOT use axios. Use ekka client only.' },
          { name: 'node-fetch', message: 'EKKA: TS MUST NOT use node-fetch. Use ekka client only.' },

          // Crypto - TS MUST NOT do crypto
          { name: 'crypto', message: 'EKKA: TS MUST NOT do crypto. Server handles all crypto.' },
          { name: 'node:crypto', message: 'EKKA: TS MUST NOT do crypto. Server handles all crypto.' },
        ],
        patterns: [
          { group: ['axios/*'], message: 'EKKA: TS MUST NOT use axios. Use ekka client only.' },
        ],
      }],

      // ========================================
      // EKKA GUARDRAILS - NO PROCESS.ENV
      // ========================================
      'no-restricted-globals': ['error',
        { name: 'process', message: 'EKKA: TS MUST NOT access process.env. Config is managed by EKKA.' },
      ],
    },
  },

  // ========================================
  // SPECIAL RULES FOR USER CODE (outside src/ekka)
  // Ban direct fetch() calls - must use ekka client
  // ========================================
  {
    files: ['src/app/**/*.{ts,tsx}', 'src/demo/**/*.{ts,tsx}'],
    rules: {
      'no-restricted-globals': ['error',
        { name: 'process', message: 'EKKA: TS MUST NOT access process.env. Config is managed by EKKA.' },
        { name: 'fetch', message: 'EKKA: Direct fetch() is forbidden. Use import { ekka } from "@ekka" instead.' },
      ],
    },
  },

  // ========================================
  // src/ekka/** - PLUMBING ZONE
  // fetch() is ALLOWED here (and ONLY here)
  // ========================================
  {
    files: ['src/ekka/**/*.{ts,tsx}'],
    rules: {
      // fetch is allowed in ekka client
      'no-restricted-globals': ['error',
        { name: 'process', message: 'EKKA: TS MUST NOT access process.env. Config is managed by EKKA.' },
      ],
    },
  },
])
