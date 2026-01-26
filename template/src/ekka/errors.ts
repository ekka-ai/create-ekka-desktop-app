/**
 * EKKA Error Classes
 *
 * Custom error types for the EKKA client library.
 * All errors extend the base EkkaError class.
 */

import { ERROR_CODES } from './constants';

// =============================================================================
// BASE ERROR
// =============================================================================

/**
 * Base error class for all EKKA errors.
 */
export class EkkaError extends Error {
  readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = 'EkkaError';
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// =============================================================================
// SPECIFIC ERRORS
// =============================================================================

/**
 * Thrown when an operation is attempted without a connection.
 */
export class EkkaNotConnectedError extends EkkaError {
  constructor() {
    super('Not connected. Call ekka.connect() first.', ERROR_CODES.NOT_CONNECTED);
    this.name = 'EkkaNotConnectedError';
  }
}

/**
 * Thrown when connection fails.
 */
export class EkkaConnectionError extends EkkaError {
  constructor(message: string) {
    super(message, 'CONNECTION_ERROR');
    this.name = 'EkkaConnectionError';
  }
}

/**
 * Thrown when an API operation fails.
 */
export class EkkaApiError extends EkkaError {
  readonly httpStatus?: number;

  constructor(message: string, code: string, httpStatus?: number) {
    super(message, code);
    this.name = 'EkkaApiError';
    this.httpStatus = httpStatus;
  }
}

/**
 * Thrown when the engine is not present.
 */
export class EkkaEngineNotPresentError extends EkkaError {
  constructor() {
    super('Engine not present. Running in demo mode.', ERROR_CODES.ENGINE_NOT_PRESENT);
    this.name = 'EkkaEngineNotPresentError';
  }
}
