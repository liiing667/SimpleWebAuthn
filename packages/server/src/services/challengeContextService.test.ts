import { assertEquals, assertThrows } from '@std/assert';
import { FakeTime } from '@std/testing/time';

import {
  createChallengeContextService,
  type NormalizedChallengeContext,
} from './challengeContextService.ts';
import { assertChallengeGenerationCurrent } from '../helpers/challengeVerification.ts';
import { ChallengeContextError } from '../errors/index.ts';

const context: NormalizedChallengeContext = {
  origins: ['https://tenant-a.example.com'],
  rpID: 'tenant-a.example.com',
  tenant: 'tenant-a',
};

Deno.test('issueChallenge() freezes origin, RP ID and tenant', async () => {
  const service = createChallengeContextService();
  const challenge = await service.issueChallenge({
    ceremony: 'authentication',
    challenge: 'rawChallenge',
    context,
  });

  const record = service.getChallenge(challenge);
  assertEquals(record?.context.origins, ['https://tenant-a.example.com']);
  assertEquals(record?.context.rpID, 'tenant-a.example.com');
  assertEquals(record?.context.tenant, 'tenant-a');
  assertEquals(record?.ceremony, 'authentication');
});

Deno.test('consumeChallenge() consumes exactly once', async () => {
  const service = createChallengeContextService();
  const challenge = await service.issueChallenge({
    ceremony: 'authentication',
    challenge: 'rawChallenge',
    context,
  });

  const first = service.consumeChallenge({
    challenge,
    ceremony: 'authentication',
    origin: 'https://tenant-a.example.com',
    rpID: 'tenant-a.example.com',
    tenant: 'tenant-a',
  });
  assertEquals(first.status, 'available');

  const second = service.consumeChallenge({
    challenge,
    ceremony: 'authentication',
    origin: 'https://tenant-a.example.com',
    rpID: 'tenant-a.example.com',
    tenant: 'tenant-a',
  });
  assertEquals(second.status, 'used');
});

Deno.test('consumeChallenge() accepts the original custom challenge for compat', async () => {
  const service = createChallengeContextService();
  const wrappedChallenge = await service.issueChallenge({
    ceremony: 'authentication',
    challenge: 'rawChallenge',
    context,
  });

  const result = service.consumeChallenge({
    challenge: 'rawChallenge',
    ceremony: 'authentication',
    origin: 'https://tenant-a.example.com',
    tenant: 'tenant-a',
  });
  assertEquals(result.status, 'available');
  assertEquals(result.record?.challenge, wrappedChallenge);
});

Deno.test('consumeChallenge() rejects another origin and burns the challenge', async () => {
  const service = createChallengeContextService();
  const challenge = await service.issueChallenge({
    ceremony: 'authentication',
    challenge: 'rawChallenge',
    context,
  });

  const crossOrigin = service.consumeChallenge({
    challenge,
    ceremony: 'authentication',
    origin: 'https://tenant-b.example.com',
    tenant: 'tenant-a',
  });
  assertEquals(crossOrigin.status, 'origin_mismatch');

  const retry = service.consumeChallenge({
    challenge,
    ceremony: 'authentication',
    origin: 'https://tenant-a.example.com',
    tenant: 'tenant-a',
  });
  assertEquals(retry.status, 'used');
});

Deno.test('consumeChallenge() rejects another tenant', async () => {
  const service = createChallengeContextService();
  const challenge = await service.issueChallenge({
    ceremony: 'authentication',
    challenge: 'rawChallenge',
    context,
  });

  const result = service.consumeChallenge({
    challenge,
    ceremony: 'authentication',
    origin: 'https://tenant-a.example.com',
    tenant: 'tenant-b',
  });
  assertEquals(result.status, 'tenant_mismatch');
});

Deno.test('consumeChallenge() requires the bound tenant to be supplied', async () => {
  const service = createChallengeContextService();
  const challenge = await service.issueChallenge({
    ceremony: 'authentication',
    challenge: 'rawChallenge',
    context,
  });

  const result = service.consumeChallenge({
    challenge,
    ceremony: 'authentication',
    origin: 'https://tenant-a.example.com',
  });
  assertEquals(result.status, 'tenant_missing');
});

Deno.test('consumeChallenge() rejects a registration challenge in authentication', async () => {
  const service = createChallengeContextService();
  const challenge = await service.issueChallenge({
    ceremony: 'registration',
    challenge: 'rawChallenge',
    context,
  });

  const result = service.consumeChallenge({
    challenge,
    ceremony: 'authentication',
    origin: 'https://tenant-a.example.com',
    tenant: 'tenant-a',
  });
  assertEquals(result.status, 'ceremony_mismatch');
});

Deno.test('cancelChallenge() prevents later consumption', async () => {
  const service = createChallengeContextService();
  const challenge = await service.issueChallenge({
    ceremony: 'authentication',
    challenge: 'rawChallenge',
    context,
  });

  assertEquals(service.cancelChallenge(challenge), true);

  const result = service.consumeChallenge({
    challenge,
    ceremony: 'authentication',
    origin: 'https://tenant-a.example.com',
    tenant: 'tenant-a',
  });
  assertEquals(result.status, 'cancelled');
});

Deno.test('reset() prevents an old challenge from reviving', async () => {
  const service = createChallengeContextService();
  const oldChallenge = await service.issueChallenge({
    ceremony: 'authentication',
    challenge: 'rawChallenge',
    context,
  });

  const oldGeneration = service.generation;
  service.reset('test restart');
  assertEquals(service.generation, oldGeneration + 1);

  const oldResult = service.consumeChallenge({
    challenge: oldChallenge,
    ceremony: 'authentication',
    origin: 'https://tenant-a.example.com',
    tenant: 'tenant-a',
  });
  assertEquals(oldResult.status, 'stale_generation');

  const newChallenge = await service.issueChallenge({
    ceremony: 'authentication',
    challenge: 'rawChallenge',
    context,
  });
  const newResult = service.consumeChallenge({
    challenge: newChallenge,
    ceremony: 'authentication',
    origin: 'https://tenant-a.example.com',
    tenant: 'tenant-a',
  });
  assertEquals(newResult.status, 'available');
});

Deno.test('legacy caller-managed challenges remain untracked by default', () => {
  const service = createChallengeContextService();

  const legacy = service.consumeChallenge({
    challenge: 'callerManagedChallenge',
    ceremony: 'authentication',
    origin: 'https://tenant-a.example.com',
    tenant: 'tenant-a',
  });
  assertEquals(legacy.tracked, false);
  assertEquals(legacy.status, 'untracked');

  const required = service.consumeChallenge({
    challenge: 'anotherCallerManagedChallenge',
    ceremony: 'authentication',
    origin: 'https://tenant-a.example.com',
    tenant: 'tenant-a',
    requireContext: true,
  });
  assertEquals(required.tracked, true);
  assertEquals(required.status, 'missing');
});

Deno.test('rememberChallenge() does not rebind a cancelled challenge', () => {
  const service = createChallengeContextService();
  service.rememberChallenge({
    challenge: 'callerManagedChallenge',
    ceremony: 'authentication',
    context,
  });
  service.cancelChallenge('callerManagedChallenge');

  service.rememberChallenge({
    challenge: 'callerManagedChallenge',
    ceremony: 'authentication',
    context: {
      origins: ['https://tenant-b.example.com'],
      rpID: 'tenant-b.example.com',
      tenant: 'tenant-b',
    },
  });

  const result = service.consumeChallenge({
    challenge: 'callerManagedChallenge',
    ceremony: 'authentication',
    origin: 'https://tenant-b.example.com',
    tenant: 'tenant-b',
  });
  assertEquals(result.status, 'cancelled');
});

Deno.test('consumeChallenge() rejects a challenge after its timeout', async () => {
  const time = new FakeTime();
  try {
    const service = createChallengeContextService();
    const challenge = await service.issueChallenge({
      ceremony: 'authentication',
      challenge: 'rawChallenge',
      context,
      timeoutMS: 1_000,
    });

    await time.tickAsync(1_001);

    const result = service.consumeChallenge({
      challenge,
      ceremony: 'authentication',
      origin: 'https://tenant-a.example.com',
      tenant: 'tenant-a',
    });
    assertEquals(result.status, 'expired');
  } finally {
    time.restore();
  }
});

Deno.test('assertChallengeGenerationCurrent() rejects an old generation at commit', () => {
  ChallengeContextService.reset();
  const record = ChallengeContextService.rememberChallenge({
    challenge: 'rawChallenge',
    ceremony: 'authentication',
    context,
  });

  ChallengeContextService.reset('simulated restart');

  const error = assertThrows(
    () =>
      assertChallengeGenerationCurrent({
        record,
        ceremony: 'authentication',
        actualOrigin: 'https://tenant-a.example.com',
        actualRPID: 'tenant-a.example.com',
        sessionTenant: 'tenant-a',
      }),
    ChallengeContextError,
  );

  assertEquals((error as ChallengeContextError).audit.stage, 'commit');
  assertEquals((error as ChallengeContextError).audit.generation, record.generation);
});
