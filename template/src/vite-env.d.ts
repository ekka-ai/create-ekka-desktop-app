/// <reference types="vite/client" />

/** App name injected from app.config.json via Vite define */
declare const __APP_NAME__: string;

interface ImportMetaEnv {
  readonly VITE_EKKA_API_URL: string;
  readonly VITE_EKKA_ENGINE_URL: string;
  readonly VITE_DEV_EMAIL: string;
  readonly VITE_DEV_PASSWORD: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
