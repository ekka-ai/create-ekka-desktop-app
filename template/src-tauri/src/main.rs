// EKKA Desktop - Tauri Stub
// Minimal shell for local development. TS uses DemoBackend.
// Production build replaces this with real src-tauri + embedded engine.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
