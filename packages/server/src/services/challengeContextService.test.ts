import { assertEquals, assertFalse, assertNotEquals, assertRejects } from '@std/assert';

import {
  createChallengeContextService,
  normalizeChallengeContext,
} from './challengeContextService.ts';
import { isoBase64URL } from '../helpers/iso/index.ts';

const rpID = 'dev.dontneeda.pw';
const origin = 'https://dev.dontneeda.pw';

Deno.test('should consume an issued challenge exactly once', async () => {
  const service = createChallengeContextService();
  const challenge = await service.issueChallenge({
    ceremony: 'authentication',
    challenge: 'totallyUniqueValueEveryTime',
    context: { expectedOrigin: origin, rpID },
    sessionKey: 'login-session-1',
  });

  const first = service.consumeChallenge({
    challenge,
    ceremony: 'authentication',
    origin,
    rpID,
    sessionKey: 'login-session-1',
  });
  assertEquals(first.tracked, true);
  assertEquals(first.status, 'available');

  const replay = service.consumeChallenge({
    challenge,
    ceremony: 'authentication',
    origin,
    rpID,
    sessionKey: 'login-session-1',
  });
  assertEquals(replay.status, 'used');
  assertEquals(replay.challengeID, first.challengeID);
});

Deno.test('should supersede a pending ceremony when a session starts again', async () => {
  const service = createChallengeContextService();
  const firstChallenge = await service.issueChallenge({
    ceremony: 'authentication',
    challenge: 'firstCeremony',
    context: { expectedOrigin: origin, rpID },
    sessionKey: 'login-session-2',
  });
  const firstRecord = service.getChallenge(firstChallenge)!;

  const secondChallenge = await service.issueChallenge({
    ceremony: 'authentication',
    challenge: 'secondCeremony',
    context: { expectedOrigin: origin, rpID },
    sessionKey: 'login-session-2',
  });
  const secondRecord = service.getChallenge(secondChallenge)!;

  assertEquals(firstRecord.status, 'cancelled');
  assertFalse(firstRecord.ceremonyGeneration === secondRecord.ceremonyGeneration);
  assertNotEquals(firstRecord.ceremonyID, secondRecord.ceremonyID);

  const stale = service.consumeChallenge({
    challenge: firstChallenge,
    ceremony: 'authentication',
    origin,
    rpID,
    sessionKey: 'login-session-2',
  });
  assertEquals(stale.status, 'cancelled');

  const current = service.consumeChallenge({
    challenge: secondChallenge,
    ceremony: 'authentication',
    origin,
    rpID,
    sessionKey: 'login-session-2',
  });
  assertEquals(current.status, 'available');
});

Deno.test('should not revive a cancelled challenge by remembering it again', async () => {
  const service = createChallengeContextService();
  const baseChallenge = isoBase64URL.fromUTF8String('cancelledCeremony');
  service.rememberChallenge({
    challenge: baseChallenge,
    ceremony: 'authentication',
    context: { expectedOrigin: origin, rpID },
    sessionKey: 'login-session-3',
  });
  assertEquals(service.cancelChallenge(baseChallenge, 'tab closed'), true);

  const remembered = service.rememberChallenge({
    challenge: baseChallenge,
    ceremony: 'authentication',
    context: { expectedOrigin: origin, rpID },
    sessionKey: 'login-session-3',
  });
  assertEquals(remembered.status, 'cancelled');

  const consumption = service.consumeChallenge({
    challenge: baseChallenge,
    ceremony: 'authentication',
    origin,
    rpID,
    sessionKey: 'login-session-3',
  });
  assertEquals(consumption.status, 'cancelled');
});

Deno.test('should reject a challenge from a previous process generation after restart', async () => {
  const service = createChallengeContextService();
  const challenge = await service.issueChallenge({
    ceremony: 'authentication',
    challenge: 'beforeRestart',
    context: { expectedOrigin: origin, rpID },
    sessionKey: 'login-session-4',
  });
  const record = service.getChallenge(challenge)!;

  service.reset('simulated restart');

  const stale = service.consumeChallenge({
    challenge,
    ceremony: 'authentication',
    origin,
    rpID,
    sessionKey: 'login-session-4',
  });
  assertEquals(stale.tracked, true);
  assertEquals(stale.status, 'stale_generation');
  assertEquals(stale.ceremonyID, record.ceremonyID);

  const retry = service.rememberChallenge({
    challenge,
    ceremony: 'authentication',
    context: { expectedOrigin: origin, rpID },
    sessionKey: 'login-session-4',
  });
  assertEquals(retry.status, 'cancelled');
  assertFalse(service.getChallenge(challenge) === retry);
});

Deno.test('should carry ceremony and challenge handles into the audit record', async () => {
  const service = createChallengeContextService();
  const challenge = await service.issueChallenge({
    ceremony: 'authentication',
    challenge: 'auditedCeremony',
    context: { expectedOrigin: origin, rpID },
    sessionKey: 'login-session-5',
    ceremonyID: 'tab-abc',
    ceremonyGeneration: 7,
  });
  const record = service.getChallenge(challenge)!;

  assertEquals(record.ceremonyID, 'tab-abc');
  assertEquals(record.ceremonyGeneration, 7);
  assertEquals(record.sessionKey, 'login-session-5');
  assertEquals(record.challengeID.length > 0, true);
  assertEquals(record.context.origins, [origin]);
});

Deno.test('should not restart a consumed ceremony generation', async () => {
  const service = createChallengeContextService();
  const challenge = await service.issueChallenge({
    ceremony: 'authentication',
    challenge: 'oneShotCeremony',
    context: { expectedOrigin: origin, rpID },
    ceremonyID: 'tab-retry',
    ceremonyGeneration: 3,
  });
  service.consumeChallenge({
    challenge,
    ceremony: 'authentication',
    origin,
    rpID,
  });

  await assertRejects(
    () =>
      service.issueChallenge({
        ceremony: 'authentication',
        challenge: 'oneShotCeremony',
        context: { expectedOrigin: origin, rpID },
        ceremonyID: 'tab-retry',
        ceremonyGeneration: 3,
      }),
    Error,
    'cannot be restarted by retry',
  );
});

Deno.test('should normalize challenge context aliases', () => {
  const context = normalizeChallengeContext({
    expectedOrigin: [origin],
    expectedRPID: rpID,
    tenantId: 'tenant-a',
  }, rpID);

  assertEquals(context, {
    origins: [origin],
    rpID,
    tenant: 'tenant-a',
    userID: undefined,
  });
});
