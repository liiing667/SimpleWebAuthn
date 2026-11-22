import { assert, assertEquals } from '@std/assert';

import { isoBase64URL } from '../helpers/iso/index.ts';

import { generateAuthenticationOptions } from './generateAuthenticationOptions.ts';
import { ChallengeContextService } from '../services/challengeContextService.ts';

const challengeString = 'dG90YWxseXJhbmRvbXZhbHVl';
const challengeBuffer = isoBase64URL.toBuffer(challengeString);

const rpID = 'simplewebauthn.dev';

Deno.test('should generate credential request options suitable for sending via JSON', async () => {
  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: [
      {
        id: '1234',
        transports: ['usb', 'nfc'],
      },
      {
        id: '5678',
        transports: ['internal'],
      },
    ],
    timeout: 1,
    challenge: challengeBuffer,
  });

  assertEquals(options, {
    rpId: 'simplewebauthn.dev',
    // base64url-encoded
    challenge: challengeString,
    allowCredentials: [
      {
        id: '1234',
        type: 'public-key',
        transports: ['usb', 'nfc'],
      },
      {
        id: '5678',
        type: 'public-key',
        transports: ['internal'],
      },
    ],
    timeout: 1,
    userVerification: 'preferred',
    extensions: undefined,
  });
});

Deno.test('defaults to 60 seconds if no timeout is specified', async () => {
  const options = await generateAuthenticationOptions({
    rpID,
    challenge: challengeBuffer,
    allowCredentials: [
      { id: '1234' },
      { id: '5678' },
    ],
  });

  assertEquals(options.timeout, 60000);
});

Deno.test('should set userVerification to "preferred" if not specified', async () => {
  const options = await generateAuthenticationOptions({
    rpID,
    challenge: challengeBuffer,
    allowCredentials: [
      { id: '1234' },
      { id: '5678' },
    ],
  });

  assertEquals(options.userVerification, 'preferred');
});

Deno.test('should not set allowCredentials if not specified', async () => {
  const options = await generateAuthenticationOptions({ rpID });

  assertEquals(options.allowCredentials, undefined);
});

Deno.test('should generate without params', async () => {
  const options = await generateAuthenticationOptions({ rpID });
  const { challenge, ...otherFields } = options;
  assertEquals(otherFields, {
    allowCredentials: undefined,
    extensions: undefined,
    rpId: rpID,
    timeout: 60000,
    userVerification: 'preferred',
  });
  assertEquals(typeof challenge, 'string');
});

Deno.test('should set userVerification if specified', async () => {
  const options = await generateAuthenticationOptions({
    rpID,
    challenge: challengeBuffer,
    allowCredentials: [
      { id: '1234' },
      { id: '5678' },
    ],
    userVerification: 'required',
  });

  assertEquals(options.userVerification, 'required');
});

Deno.test('should set extensions if specified', async () => {
  const options = await generateAuthenticationOptions({
    rpID,
    challenge: challengeBuffer,
    allowCredentials: [
      { id: '1234' },
      { id: '5678' },
    ],
    extensions: { appid: 'simplewebauthn' },
  });

  assertEquals(options.extensions, { appid: 'simplewebauthn' });
});

Deno.test('should generate a challenge if one is not provided', async () => {
  // @ts-ignore 2345
  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: [
      { id: '1234' },
      { id: '5678' },
    ],
  });

  // Assert basic properties of the challenge
  assert(options.challenge.length >= 16);
  assert(isoBase64URL.isBase64URL(options.challenge));
});

Deno.test('should treat string challenges as UTF-8 strings', async () => {
  const options = await generateAuthenticationOptions({
    rpID,
    challenge: 'こんにちは',
  });

  assertEquals(
    options.challenge,
    '44GT44KT44Gr44Gh44Gv',
  );
});

Deno.test('should bind ceremony/session metadata into the challenge', async () => {
  ChallengeContextService.reset();
  const options = await generateAuthenticationOptions({
    rpID,
    challenge: challengeString,
    ceremonyContext: {
      expectedOrigin: 'https://simplewebauthn.dev',
      sessionKey: 'login-session',
    },
  });

  assert(options.ceremonyID);
  assert(options.ceremonyGeneration);
  assert(options.challengeID);
  assertEquals(options.ceremony?.id, options.ceremonyID);
  assertEquals(options.ceremony?.sessionKey, 'login-session');
  assert(options.challenge !== challengeString);

  const record = ChallengeContextService.getChallenge(options.challenge);
  assertEquals(record?.ceremonyID, options.ceremonyID);
  assertEquals(record?.ceremonyGeneration, options.ceremonyGeneration);
  assertEquals(record?.sessionKey, 'login-session');
});

Deno.test('should supersede a previous start in the same login session', async () => {
  ChallengeContextService.reset();
  const first = await generateAuthenticationOptions({
    rpID,
    challenge: 'firstChallenge',
    ceremonyContext: {
      expectedOrigin: 'https://simplewebauthn.dev',
      sessionKey: 'retry-session',
    },
  });
  const second = await generateAuthenticationOptions({
    rpID,
    challenge: 'secondChallenge',
    ceremonyContext: {
      expectedOrigin: 'https://simplewebauthn.dev',
      sessionKey: 'retry-session',
    },
  });

  assert(second.ceremonyGeneration! > first.ceremonyGeneration!);

  const stale = ChallengeContextService.consumeChallenge({
    challenge: first.challenge,
    ceremony: 'authentication',
    origin: 'https://simplewebauthn.dev',
    rpID,
    sessionKey: 'retry-session',
  });
  assertEquals(stale.status, 'cancelled');

  const current = ChallengeContextService.consumeChallenge({
    challenge: second.challenge,
    ceremony: 'authentication',
    origin: 'https://simplewebauthn.dev',
    rpID,
    sessionKey: 'retry-session',
  });
  assertEquals(current.status, 'available');
});
