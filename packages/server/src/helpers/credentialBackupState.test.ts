import {
  assert,
  assertEquals,
  assertFalse,
  assertThrows,
} from '@std/assert';

import {
  CURRENT_BACKUP_POLICY_VERSION,
  freezeCredentialBackupState,
  reconcileCredentialBackupState,
  withReconciledBackupState,
} from './credentialBackupState.ts';
import { InvalidBackupFlags } from './parseBackupFlags.ts';
import type { WebAuthnCredential } from '../types/index.ts';

const baseCredential: WebAuthnCredential = {
  id: 'credential-id',
  publicKey: new Uint8Array([1, 2, 3]),
  counter: 0,
};

const legacySingleDevice: WebAuthnCredential = {
  ...baseCredential,
};

const modernSingleDevice: WebAuthnCredential = {
  ...baseCredential,
  credentialDeviceType: 'singleDevice',
  credentialBackedUp: false,
  backupPolicyVersion: CURRENT_BACKUP_POLICY_VERSION,
};

const modernMultiDeviceNotBackedUp: WebAuthnCredential = {
  ...baseCredential,
  credentialDeviceType: 'multiDevice',
  credentialBackedUp: false,
  backupPolicyVersion: CURRENT_BACKUP_POLICY_VERSION,
};

const modernMultiDeviceBackedUp: WebAuthnCredential = {
  ...baseCredential,
  credentialDeviceType: 'multiDevice',
  credentialBackedUp: true,
  backupPolicyVersion: CURRENT_BACKUP_POLICY_VERSION,
};

Deno.test('freezeCredentialBackupState should freeze a single-device credential', () => {
  const state = freezeCredentialBackupState({ be: false, bs: false });

  assertEquals(state.credentialDeviceType, 'singleDevice');
  assertEquals(state.credentialBackedUp, false);
  assertEquals(state.backupPolicyVersion, CURRENT_BACKUP_POLICY_VERSION);
  assertFalse(state.migrated);
});

Deno.test('freezeCredentialBackupState should freeze a backed-up multi-device credential', () => {
  const state = freezeCredentialBackupState({ be: true, bs: true });

  assertEquals(state.credentialDeviceType, 'multiDevice');
  assertEquals(state.credentialBackedUp, true);
  assertEquals(state.backupPolicyVersion, CURRENT_BACKUP_POLICY_VERSION);
});

Deno.test('freezeCredentialBackupState should reject the impossible BE=0, BS=1 combination', () => {
  assertThrows(
    () => freezeCredentialBackupState({ be: false, bs: true }),
    InvalidBackupFlags,
    'impossible',
  );
});

Deno.test('reconcile should recoverably migrate a legacy single-device credential', () => {
  const state = reconcileCredentialBackupState({
    credential: legacySingleDevice,
    observed: { be: false, bs: false },
  });

  assertEquals(state.credentialDeviceType, 'singleDevice');
  assertEquals(state.credentialBackedUp, false);
  assertEquals(state.backupPolicyVersion, CURRENT_BACKUP_POLICY_VERSION);
  assert(state.migrated);
});

Deno.test(
  'reconcile should recoverably migrate a legacy credential that is now multi-device',
  () => {
    const state = reconcileCredentialBackupState({
      credential: legacySingleDevice,
      observed: { be: true, bs: true },
    });

    assertEquals(state.credentialDeviceType, 'multiDevice');
    assertEquals(state.credentialBackedUp, true);
    assertEquals(state.backupPolicyVersion, CURRENT_BACKUP_POLICY_VERSION);
    assert(state.migrated);
  },
);

Deno.test('reconcile should reject a BE=0, BS=1 response for a legacy credential', () => {
  assertThrows(
    () =>
      reconcileCredentialBackupState({
        credential: legacySingleDevice,
        observed: { be: false, bs: true },
      }),
    InvalidBackupFlags,
    'impossible',
  );
});

Deno.test('reconcile should keep a single-device credential single-device', () => {
  const state = reconcileCredentialBackupState({
    credential: modernSingleDevice,
    observed: { be: false, bs: false },
  });

  assertEquals(state.credentialDeviceType, 'singleDevice');
  assertEquals(state.credentialBackedUp, false);
  assertFalse(state.migrated);
});

Deno.test(
  'reconcile should upgrade a single-device credential when it gains backup eligibility',
  () => {
    const state = reconcileCredentialBackupState({
      credential: modernSingleDevice,
      observed: { be: true, bs: false },
    });

    assertEquals(state.credentialDeviceType, 'multiDevice');
    assertEquals(state.credentialBackedUp, false);
    assertFalse(state.migrated);
  },
);

Deno.test(
  'reconcile should never downgrade a multi-device credential back to single-device',
  () => {
    // A restored device can surface BE=0 even though the credential was persisted as multi-device
    const state = reconcileCredentialBackupState({
      credential: modernMultiDeviceNotBackedUp,
      observed: { be: false, bs: false },
    });

    assertEquals(state.credentialDeviceType, 'multiDevice');
    assertEquals(state.credentialBackedUp, false);
  },
);

Deno.test('reconcile should not regress backup state when a response claims BS=false again', () => {
  const state = reconcileCredentialBackupState({
    credential: modernMultiDeviceBackedUp,
    observed: { be: true, bs: false },
  });

  assertEquals(state.credentialDeviceType, 'multiDevice');
  assertEquals(state.credentialBackedUp, true);
});

Deno.test(
  'reconcile should retain multi-device status when a restored device clears both flags',
  () => {
    const state = reconcileCredentialBackupState({
      credential: modernMultiDeviceBackedUp,
      observed: { be: false, bs: false },
    });

    assertEquals(state.credentialDeviceType, 'multiDevice');
    assertEquals(state.credentialBackedUp, true);
  },
);

Deno.test('reconcile should advance backup state from not-backed-up to backed-up', () => {
  const state = reconcileCredentialBackupState({
    credential: modernMultiDeviceNotBackedUp,
    observed: { be: true, bs: true },
  });

  assertEquals(state.credentialDeviceType, 'multiDevice');
  assertEquals(state.credentialBackedUp, true);
});

Deno.test('reconcile should reject a BE=0, BS=1 response contradicting a modern record', () => {
  assertThrows(
    () =>
      reconcileCredentialBackupState({
        credential: modernSingleDevice,
        observed: { be: false, bs: true },
      }),
    InvalidBackupFlags,
    'impossible',
  );
});

Deno.test(
  'reconcile should converge to the same record under concurrent conflicting responses',
  () => {
    // Two concurrent logins (one BE=1/BS=1, one stale BE=0/BS=0) start from the same record
    const first = reconcileCredentialBackupState({
      credential: modernMultiDeviceNotBackedUp,
      observed: { be: true, bs: true },
    });
    const second = reconcileCredentialBackupState({
      credential: modernMultiDeviceNotBackedUp,
      observed: { be: false, bs: false },
    });

    const persistedFirst = withReconciledBackupState(
      modernMultiDeviceNotBackedUp,
      first,
    );
    const persistedSecond = withReconciledBackupState(
      modernMultiDeviceNotBackedUp,
      second,
    );

    assertEquals(persistedFirst.credentialDeviceType, 'multiDevice');
    assertEquals(persistedSecond.credentialDeviceType, 'multiDevice');
    assertEquals(persistedFirst.credentialBackedUp, true);

    // Chaining the stale response after the backup was persisted keeps the record consistent
    const chained = reconcileCredentialBackupState({
      credential: persistedFirst,
      observed: { be: false, bs: false },
    });
    assertEquals(chained.credentialBackedUp, true);
    assertEquals(chained.credentialDeviceType, 'multiDevice');
  },
);

Deno.test('withReconciledBackupState should not mutate the original credential', () => {
  const state = reconcileCredentialBackupState({
    credential: modernMultiDeviceNotBackedUp,
    observed: { be: true, bs: true },
  });
  const updated = withReconciledBackupState(modernMultiDeviceNotBackedUp, state);

  assertEquals(modernMultiDeviceNotBackedUp.credentialBackedUp, false);
  assertEquals(updated.credentialBackedUp, true);
  assertEquals(updated.credentialDeviceType, 'multiDevice');
  assertEquals(updated.backupPolicyVersion, CURRENT_BACKUP_POLICY_VERSION);
  assertEquals(updated.id, baseCredential.id);
});

Deno.test('reconcile should stamp the current policy version onto older-versioned records', () => {
  const older: WebAuthnCredential = {
    ...baseCredential,
    credentialDeviceType: 'multiDevice',
    credentialBackedUp: true,
    backupPolicyVersion: 0,
  };

  const state = reconcileCredentialBackupState({
    credential: older,
    observed: { be: true, bs: false },
  });

  assertEquals(state.backupPolicyVersion, CURRENT_BACKUP_POLICY_VERSION);
  assertEquals(state.credentialDeviceType, 'multiDevice');
  assertEquals(state.credentialBackedUp, true);
  assertFalse(state.migrated);
});
