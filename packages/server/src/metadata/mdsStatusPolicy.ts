import type { AuthenticatorStatus, StatusReport } from './mdsTypes.ts';
import { SimpleWebAuthnError } from '../errors/index.ts';

/**
 * Authenticator statuses that indicate a security incident severe enough to block registration.
 *
 * The first four are the "compromised" statuses described in the FIDO Metadata Service spec.
 * `REVOKED` indicates that the authenticator's certification (and so its trustworthiness) has
 * been withdrawn.
 *
 * See https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-interface
 */
export const HIGH_RISK_AUTHENTICATOR_STATUSES: ReadonlySet<AuthenticatorStatus> = new Set([
  'USER_VERIFICATION_BYPASS',
  'ATTESTATION_KEY_COMPROMISE',
  'USER_KEY_REMOTE_COMPROMISE',
  'USER_KEY_PHYSICAL_COMPROMISE',
  'REVOKED',
]);

/**
 * Statuses that indicate a trustworthy, FIDO-certified authenticator. Authenticators in any other
 * known status are not blocked, but the status is recorded so the decision to trust them remains
 * visible.
 */
const TRUSTED_AUTHENTICATOR_STATUSES: ReadonlySet<AuthenticatorStatus> = new Set([
  'FIDO_CERTIFIED',
  'FIDO_CERTIFIED_L1',
  'FIDO_CERTIFIED_L1plus',
  'FIDO_CERTIFIED_L2',
  'FIDO_CERTIFIED_L2plus',
  'FIDO_CERTIFIED_L3',
  'FIDO_CERTIFIED_L3plus',
]);

/**
 * The outcome of evaluating an authenticator's MDS `statusReports` against the status policy.
 */
export type MDSStatusPolicyResult = {
  /**
   * `true` when one or more status reports carry a high-risk status. Registration must be blocked
   * when this is `true`.
   */
  blocked: boolean;
  /** The high-risk status that triggered the block, when `blocked` is `true` */
  blockingStatus?: AuthenticatorStatus;
  /** Every status observed in the status reports, in report order */
  observedStatuses: AuthenticatorStatus[];
  /**
   * `true` when none of the observed statuses indicate a FIDO-certified authenticator. Such
   * authenticators are not blocked, but the unknown/untrusted status should be recorded.
   */
  hasUntrustedStatus: boolean;
};

/**
 * Evaluate MDS status reports against the library's status policy.
 *
 * High-risk statuses (compromise reports and `REVOKED`) produce a blocking result. Everything
 * else is allowed through, with untrusted/unknown statuses flagged so that callers can record
 * them. An empty list of reports (e.g. for a locally-cached metadata statement that MDS has no
 * status information for) is treated as an unknown status and flagged, but not blocked.
 */
export function evaluateMDSStatusReports(
  statusReports: StatusReport[] | undefined,
): MDSStatusPolicyResult {
  const observedStatuses = (statusReports ?? []).map((report) => report.status);

  const blockingReport = observedStatuses.find((status) =>
    HIGH_RISK_AUTHENTICATOR_STATUSES.has(status)
  );

  const hasTrustedStatus = observedStatuses.some((status) =>
    TRUSTED_AUTHENTICATOR_STATUSES.has(status)
  );

  return {
    blocked: blockingReport !== undefined,
    blockingStatus: blockingReport,
    observedStatuses,
    hasUntrustedStatus: !hasTrustedStatus,
  };
}

/**
 * Evaluate MDS status reports and throw a typed error when a high-risk status is present. Returns
 * the policy result otherwise so that callers can log untrusted/unknown statuses before
 * continuing.
 *
 * @throws {SimpleWebAuthnError} with code `METADATA_HIGH_RISK_STATUS`
 */
export function assertNoHighRiskMDSStatus(
  aaguid: string,
  statusReports: StatusReport[] | undefined,
): MDSStatusPolicyResult {
  const result = evaluateMDSStatusReports(statusReports);

  if (result.blocked) {
    throw new SimpleWebAuthnError({
      message: `Registration blocked: metadata for aaguid "${aaguid}" reports high-risk status ` +
        `"${result.blockingStatus}"`,
      code: 'METADATA_HIGH_RISK_STATUS',
    });
  }

  return result;
}
