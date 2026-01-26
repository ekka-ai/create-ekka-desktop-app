# create-ekka-desktop-app

Scaffold a new EKKA desktop app with one command. Zero config, batteries included.

## Quick Start

```bash
npx create-ekka-desktop-app my-app
cd my-app
npm install
npm run tauri:dev
```

That's it. You now have a native desktop app running.

## What You Get

```
my-app/
├── src/
│   ├── app/App.tsx        # Your app (start here)
│   ├── demo/              # Demo UI (delete when ready)
│   └── ekka/              # EKKA SDK (do not modify)
├── src-tauri/             # Tauri (Rust) shell
├── branding/              # App name, icon, bundle ID
├── package.json
└── vite.config.ts
```

## Development

```bash
# Web browser (fast reload)
npm start

# Desktop window (native)
npm run tauri:dev
```

## Build

```bash
# Create distributable .app
npm run tauri:build
```

Output: `src-tauri/target/release/bundle/macos/<AppName>.app`

## Customize Branding

Edit `branding/app.json`:

```json
{
  "name": "My App",
  "bundleId": "com.mycompany.myapp",
  "version": "1.0.0"
}
```

Replace `branding/icon.icns` with your app icon.

## Project Structure

| Path | Purpose |
|------|---------|
| `src/app/App.tsx` | **Your app code starts here** |
| `src/demo/` | Demo UI - delete when you're ready to build your own |
| `src/ekka/` | EKKA SDK - provides secure APIs (do not modify) |
| `src-tauri/` | Tauri shell - handles native window, builds .app |
| `branding/` | App name, icon, bundle ID |

## EKKA SDK

The app includes the EKKA SDK at `src/ekka/`. It provides:

- **Secure key-value storage** - Data persists across sessions
- **Background work queues** - Run async tasks reliably
- **Policy enforcement** - All operations are auditable

```tsx
import { ekka } from './ekka';

// Store data
await ekka.store.set('key', 'value');

// Retrieve data
const value = await ekka.store.get('key');

// Queue background work
await ekka.work.enqueue({ task: 'process', data: {...} });
```

## Demo Mode

The app runs in **demo mode** by default - all data is stored in memory. This lets you develop and test without any backend setup.

When you're ready for production:
1. Build with the EKKA engine sidecar (via `ekka-desktop-build`)
2. The SDK automatically connects to the real backend

## Requirements

- Node.js 18+
- Rust (for Tauri builds)
- Xcode Command Line Tools (macOS)

## Commands

| Command | Description |
|---------|-------------|
| `npm start` | Start dev server (web) |
| `npm run tauri:dev` | Start dev server (desktop) |
| `npm run tauri:build` | Build distributable app |
| `npm run lint` | Run ESLint |
| `npm run build` | Build frontend only |

## FAQ

**Q: How do I change the app name?**
Edit `branding/app.json` and set the `name` field.

**Q: How do I change the app icon?**
Replace `branding/icon.icns` with your icon file.

**Q: How do I remove the demo UI?**
Delete `src/demo/` and update `src/main.tsx` to render your own component.

**Q: Where is my data stored in demo mode?**
In memory. It resets when you restart the app.

**Q: How do I connect to a real backend?**
Build with `ekka-desktop-build` which injects the EKKA engine sidecar.

## License

MIT
