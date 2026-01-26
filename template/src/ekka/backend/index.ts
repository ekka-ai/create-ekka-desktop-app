/**
 * EKKA Backend Module
 *
 * Backend interface and implementations.
 * NO direct function exports to prevent bypass.
 */

// Interface
export type { Backend } from './interface';

// Demo backend
export { DemoBackend, demoBackend } from './demo';

// Engine backend
export { EngineBackend, engineBackend } from './engine';
