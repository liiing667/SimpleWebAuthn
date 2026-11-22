import { assertEquals } from '@std/assert';
import { afterEach, describe, it } from '@std/testing/bdd';

import { RegistrationChallengeService } from './registrationChallengeService.ts';

describe('RegistrationChallengeService', () => {
  afterEach(() => {
    RegistrationChallengeService.reset();
  });

  it('should consume a remembered challenge exactly once', () => {
    RegistrationChallengeService.rememberChallenge({
      challenge: 'challenge',
      userID: 'user',
      userIDWasProvided: true,
    });

    const first = RegistrationChallengeService.consumeChallenge('challenge');
    assertEquals(first.tracked, true);
    if (first.tracked) {
      assertEquals(first.status, 'available');
    }

    const second = RegistrationChallengeService.consumeChallenge('challenge');
    assertEquals(second.tracked, true);
    if (second.tracked) {
      assertEquals(second.status, 'used');
    }
  });

  it('should leave challenges it did not issue untracked', () => {
    const result = RegistrationChallengeService.consumeChallenge('not-issued-here');
    assertEquals(result.tracked, false);
  });

  it('should not revive a consumed challenge', () => {
    RegistrationChallengeService.rememberChallenge({
      challenge: 'challenge',
      userID: 'user',
      userIDWasProvided: true,
    });
    assertEquals(
      RegistrationChallengeService.consumeChallenge('challenge').tracked,
      true,
    );

    RegistrationChallengeService.rememberChallenge({
      challenge: 'challenge',
      userID: 'user',
      userIDWasProvided: true,
    });

    const result = RegistrationChallengeService.consumeChallenge('challenge');
    assertEquals(result.tracked, true);
    if (result.tracked) {
      assertEquals(result.status, 'used');
    }
  });

  it('should consume a credential ID exactly once', () => {
    const first = RegistrationChallengeService.consumeCredential({
      credentialID: 'credential',
      userID: 'user',
    });
    assertEquals(first.consumed, true);

    const second = RegistrationChallengeService.consumeCredential({
      credentialID: 'credential',
      userID: 'another-user',
    });
    assertEquals(second.consumed, false);
    assertEquals(second.record.userID, 'user');
  });

  it('should return consumed credentials for the same user only', () => {
    RegistrationChallengeService.consumeCredential({
      credentialID: 'credential-a',
      userID: 'user-a',
      userIDWasProvided: true,
    });
    RegistrationChallengeService.consumeCredential({
      credentialID: 'credential-b',
      userID: 'user-b',
      userIDWasProvided: true,
    });

    assertEquals(
      RegistrationChallengeService.getCredentialsForUser('user-a').map((record) =>
        record.credentialID
      ),
      ['credential-a'],
    );
  });

  it('should forget everything when reset', () => {
    RegistrationChallengeService.rememberChallenge({
      challenge: 'challenge',
      userID: 'user',
      userIDWasProvided: true,
    });
    RegistrationChallengeService.consumeCredential({ credentialID: 'credential' });

    RegistrationChallengeService.reset();

    assertEquals(RegistrationChallengeService.consumeChallenge('challenge').tracked, false);
    assertEquals(
      RegistrationChallengeService.consumeCredential({ credentialID: 'credential' }).consumed,
      true,
    );
  });
});
