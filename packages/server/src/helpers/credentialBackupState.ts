import type { CredentialDeviceType, WebAuthnCredential } from '../types/index.ts';

import { InvalidBackupFlags } from './parseBackupFlags.ts';

/**
 * The current version of the backup-state policy used when persisting a credential's backup
 * eligibility and backup state.
 *
 * Relying Parties store this alongside a credential so that records produced by an older policy
 * can be identified and recoverably migrated instead of being misinterpreted after the policy
 * changes. The value is frozen onto a credential at registration time.
 */
export const CURRENT_BACKUP_POLICY_VERSION = 1;

/**
 * Observed backup flags for a credential, as decoded from the BE (Backup Eligibility) and BS
 * (Backup State) bits of an authenticator data structure.
 */
export type ObservedBackupFlags = {
  /** Value of the Backup Eligibility (BE) flag. */
  be: boolean;
  /** Value of the Backup State (BS) flag. */
  bs: boolean;
};

/**
 * The reconciled, persistable backup state of a credential. Every value here is safe to write
 * back to storage verbatim:
 *
 * - `credentialDeviceType` is the credential's frozen category (from the BE flag at registration)
 * - `credentialBackedUp` is the monotonic backup state (from the BS flag)
 * - `backupPolicyVersion` is the policy version that produced these values
 * - `migrated` is `true` when a legacy record (one without a policy version) was recovered
 */
export type ReconciledCredentialBackupState = {
  credentialDeviceType: CredentialDeviceType;
  credentialBackedUp: boolean;
  backupPolicyVersion: number;
  /**
   * Whether the persisted credential was missing a backup policy version (i.e. it was stored by a
   * previous version of the library) and has just been migrated. Relying Parties can use this to
   * know when to write the migrated values back to their database.
   */
  migrated: boolean;
};

/**
 * Options for {@link reconcileCredentialBackupState}.
 */
export type ReconcileCredentialBackupStateOpts = {
  /**
   * The credential as currently persisted by the Relying Party. Legacy credentials that predate
   * the backup-state fields may omit `credentialDeviceType`, `credentialBackedUp`, and
   * `backupPolicyVersion`.
   */
  credential: WebAuthnCredential;
  /**
   * The BE/BS flags observed in the authenticator data of the response being verified.
   */
  observed: ObservedBackupFlags;
};

/**
 * Reconcile the backup flags observed in an authenticator response with the backup state
 * persisted for a credential, and return the values that should be stored going forward.
 *
 * The WebAuthn specification fixes the Backup Eligibility (BE) flag for the lifetime of a
 * credential while the Backup State (BS) flag can change as a credential gets backed up and
 * restored. Relying Parties therefore need a single, recoverable source of truth instead of
 * trusting the flags of any individual response:
 *
 * - **Legacy records** (no `backupPolicyVersion`) are migrated to the current policy using the
 *   observed flags. The credential remains usable, and the migration is reported via `migrated`.
 * - **Single-device credentials** stay single-device forever. An observed `bs: true` without
 *   backup eligibility is the spec-impossible `BE=0, BS=1` combination and raises
 *   {@link InvalidBackupFlags}, matching the library's historical behavior.
 * - **Multi-device credentials** stay multi-device forever. An observed `be: false` after
 *   registration (for example a response from a restored device that cleared its flags) can never
 *   downgrade the credential back to single-device.
 * - **Backup state is monotonic.** Once a credential has been observed as backed up, a later
 *   response claiming `bs: false` (for example one generated before a sync completed) is treated
 *   as stale data and the persisted `credentialBackedUp: true` is retained. The policy can only
 *   move forward, never regress.
 *
 * Because the reconciliation is purely functional and only ever advances state, concurrent
 * authentications or registrations racing to persist the same credential converge on identical
 * values instead of producing contradictory `BE`/`BS` combinations.
 */
export function reconcileCredentialBackupState(
  options: ReconcileCredentialBackupStateOpts,
): ReconciledCredentialBackupState {
  const { credential, observed } = options;
  const { be, bs } = observed;

  // The WebAuthn spec requires BS to imply BE. Reject this combination explicitly so that an
  // authenticator (or a forged response) can never smuggle a backed-up single-device credential
  // into storage.
  if (!be && bs) {
    throw new InvalidBackupFlags(
      'Single-device credential indicated that it was backed up, which should be impossible.',
    );
  }

  const observedDeviceType: CredentialDeviceType = be ? 'multiDevice' : 'singleDevice';

  const isLegacyRecord = credential.backupPolicyVersion === undefined;

  if (isLegacyRecord) {
    /**
     * Recoverable migration of a record persisted before backup state was tracked. Trust the
     * observed flags once (they have already been validated above) and stamp the current policy
     * version onto the credential so that all future responses are reconciled against it.
     */
    return {
      credentialDeviceType: observedDeviceType,
      credentialBackedUp: bs,
      backupPolicyVersion: CURRENT_BACKUP_POLICY_VERSION,
      migrated: true,
    };
  }

  /**
   * Modern record: the credential's device type was frozen at registration and can only stay the
   * same or be upgraded. A single-device credential can become multi-device when its
   * authenticator gains backup eligibility, but a multi-device credential can never be downgraded
   * back to single-device regardless of what an individual response claims.
   */
  const persistedDeviceType = credential.credentialDeviceType ?? 'singleDevice';

  const credentialDeviceType: CredentialDeviceType =
    persistedDeviceType === 'multiDevice' || observedDeviceType === 'multiDevice'
      ? 'multiDevice'
      : 'singleDevice';

  /**
   * Backup state is monotonic: it can flip from `false` to `true` once, and then never back. A
   * single-device credential can never be backed up, so its state is always `false`.
   */
  const credentialBackedUp = credentialDeviceType === 'multiDevice'
    && (credential.credentialBackedUp === true || bs);

  /**
   * Bump the policy version if this response observed a legitimate upgrade, so that the persisted
   * record always reflects the newest policy applied to it without ever allowing a regression.
   */
  const existingPolicyVersion = credential.backupPolicyVersion ?? 0;
  const backupPolicyVersion = Math.max(existingPolicyVersion, CURRENT_BACKUP_POLICY_VERSION);

  return {
    credentialDeviceType,
    credentialBackedUp,
    backupPolicyVersion,
    migrated: false,
  };
}

/**
 * Freeze the backup-related fields of a credential at registration time. The values returned here
 * are the single source of truth that every later authentication is reconciled against.
 *
 * Like {@link reconcileCredentialBackupState} this rejects the spec-impossible `BE=0, BS=1`
 * combination.
 */
export function freezeCredentialBackupState(
  observed: ObservedBackupFlags,
): ReconciledCredentialBackupState {
  const { be, bs } = observed;

  if (!be && bs) {
    throw new InvalidBackupFlags(
      'Single-device credential indicated that it was backed up, which should be impossible.',
    );
  }

  return {
    credentialDeviceType: be ? 'multiDevice' : 'singleDevice',
    credentialBackedUp: bs,
    backupPolicyVersion: CURRENT_BACKUP_POLICY_VERSION,
    migrated: false,
  };
}

/**
 * Apply reconciled backup state to a credential and return a new credential object ready to be
 * persisted. The original credential is not mutated so that concurrent verification flows cannot
 * corrupt each other's in-memory state.
 */
export function withReconciledBackupState(
  credential: WebAuthnCredential,
  state: ReconciledCredentialBackupState,
): WebAuthnCredential {
  return {
    ...credential,
    credentialDeviceType: state.credentialDeviceType,
    credentialBackedUp: state.credentialBackedUp,
    backupPolicyVersion: state.backupPolicyVersion,
  };
}
