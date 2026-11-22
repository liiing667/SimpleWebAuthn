import { convertAAGUIDToString } from './convertAAGUIDToString.ts';
import { isoUint8Array } from './iso/index.ts';
import type { Uint8Array_ } from '../types/index.ts';

/**
 * Normalize an AAGUID into a comparable form.
 *
 * AAGUIDs appear both as hyphenated UUID strings and as 32-character hex strings (for example in
 * `authenticatorGetInfo.aaguid`). Treating them equivalently keeps metadata lookups and identity
 * checks from depending on which representation a caller or MDS entry happens to use.
 */
export function normalizeAAGUID(aaguid: string | Uint8Array_): string {
  if (aaguid instanceof Uint8Array) {
    return convertAAGUIDToString(aaguid).toLowerCase();
  }

  return aaguid.replaceAll('-', '').toLowerCase();
}

/**
 * Compare two AAGUIDs regardless of UUID formatting or case.
 */
export function areAAGUIDsEqual(
  aaguidA: string | Uint8Array_,
  aaguidB: string | Uint8Array_,
): boolean {
  return normalizeAAGUID(aaguidA) === normalizeAAGUID(aaguidB);
}

/**
 * Convert an AAGUID string into the raw 16 bytes used in authenticator data and certificate
 * extensions. Raw byte inputs are returned as-is.
 */
export function convertAAGUIDToBytes(aaguid: string | Uint8Array_): Uint8Array_ {
  if (aaguid instanceof Uint8Array) {
    return aaguid;
  }

  const hex = aaguid.replaceAll('-', '');
  if (!/^[0-9a-fA-F]{32}$/.test(hex)) {
    throw new Error(`AAGUID "${aaguid}" was not a valid UUID or 32-character hex string`);
  }

  return isoUint8Array.fromHex(hex.toLowerCase());
}
