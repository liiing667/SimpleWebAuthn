import type { Base64URLString } from '../types/index.ts';
import { SimpleWebAuthnError } from '../errors/index.ts';
import { isoBase64URL } from './iso/index.ts';

/**
 * Raised when a credential's `clientDataJSON` cannot be decoded before challenge/origin
 * verification begins. Keeping this as a structured error lets callers attach the credential
 * identity and the `client_data` rejection stage to their session audit.
 */
export class ClientDataJSONError extends SimpleWebAuthnError {
  readonly stage = 'client_data';

  constructor(message: string, cause?: Error) {
    super({ message, code: 'INVALID_CLIENT_DATA_JSON', cause });
    this.name = 'ClientDataJSONError';
  }
}

/**
 * Decode an authenticator's base64url-encoded clientDataJSON to JSON
 */
export function decodeClientDataJSON(data: Base64URLString): ClientDataJSON {
  let clientData: ClientDataJSON;
  try {
    const toString = isoBase64URL.toUTF8String(data);
    clientData = JSON.parse(toString);
  } catch (error) {
    throw new ClientDataJSONError(
      'Credential clientDataJSON could not be decoded',
      error instanceof Error ? error : undefined,
    );
  }

  if (!clientData || typeof clientData !== 'object') {
    throw new ClientDataJSONError('Credential clientDataJSON was not an object');
  }

  return _decodeClientDataJSONInternals.stubThis(clientData);
}

export type ClientDataJSON = {
  type: string;
  challenge: string;
  origin: string;
  crossOrigin?: boolean;
  topOrigin?: string;
  tokenBinding?: {
    id?: string;
    status: 'present' | 'supported' | 'not-supported';
  };
};

/**
 * Make it possible to stub the return value during testing
 * @ignore Don't include this in docs output
 */
export const _decodeClientDataJSONInternals = {
  stubThis: (value: ClientDataJSON) => value,
};
