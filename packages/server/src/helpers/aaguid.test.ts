import { assert, assertEquals, assertThrows } from '@std/assert';

import { areAAGUIDsEqual, convertAAGUIDToBytes, normalizeAAGUID } from './aaguid.ts';
import { isoUint8Array } from './iso/index.ts';

const aaguid = 'eccafc38-1f85-41ed-8f3f-ea17705ae8b7';

Deno.test('should normalize hyphenated and non-hyphenated AAGUIDs equivalently', () => {
  assertEquals(normalizeAAGUID(aaguid), 'eccafc381f8541ed8f3fea17705ae8b7');
  assertEquals(normalizeAAGUID(aaguid.toUpperCase()), 'eccafc381f8541ed8f3fea17705ae8b7');
  assertEquals(normalizeAAGUID(aaguid.replaceAll('-', '')), 'eccafc381f8541ed8f3fea17705ae8b7');
});

Deno.test('should compare AAGUIDs regardless of representation', () => {
  const bytes = convertAAGUIDToBytes(aaguid);

  assert(areAAGUIDsEqual(aaguid, bytes));
  assert(areAAGUIDsEqual(aaguid, aaguid.replaceAll('-', '').toUpperCase()));
  assertEquals(areAAGUIDsEqual(aaguid, '00000000-0000-0000-0000-000000000000'), false);
});

Deno.test('should convert AAGUID strings to their raw bytes', () => {
  assertEquals(
    isoUint8Array.toHex(convertAAGUIDToBytes(aaguid)),
    'eccafc381f8541ed8f3fea17705ae8b7',
  );
});

Deno.test('should reject malformed AAGUID strings', () => {
  assertThrows(() => convertAAGUIDToBytes('not-an-aaguid'), Error, 'was not a valid');
});
