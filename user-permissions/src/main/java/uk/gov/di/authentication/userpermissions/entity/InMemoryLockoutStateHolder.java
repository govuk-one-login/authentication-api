package uk.gov.di.authentication.userpermissions.entity;

/**
 * In-memory state holder for communicating lockout status between UserActionsManager and
 * PermissionDecisionManager within a single Lambda invocation.
 *
 * <p>This exists as a workaround for reauth journeys when supportReauthSignoutEnabled is true. In
 * that scenario, sentSmsOtpNotification increments the count and resets it when the limit is
 * exceeded, but does NOT create a Redis block. The subsequent call to canSendSmsOtpNotification
 * checks Redis for blocks, but finds none because reauth users aren't blocked there.
 *
 * <p>We explicitly chose not to enable recording of the Redis block on reauth journeys because of
 * knock-on consequences to other places in the API that check these blocks. For example, if we
 * record a block on a reauth journey in Redis, the next time the user signs in they will also see
 * the block, which is not intended. During reauthentication journeys, users should be signed out,
 * not locked out.
 *
 * <p>Since UserActionsManager (action tracking) and PermissionDecisionManager (permission checking)
 * are intentionally segregated, this holder bridges the gap by allowing the action tracker to
 * signal that a limit was exceeded, which the permission checker can then read.
 *
 * <p>TODO: Remove this workaround when lockout storage is refactored. The permission check should
 * be able to determine if limits are exceeded without relying on Redis blocks or this in-memory
 * bridge. We do similar with AuthenticationAttemptsService for other lockout types, but that has
 * not been implemented for SMS sending lockouts for reauth yet.
 */
public class InMemoryLockoutStateHolder {

    private boolean reauthSmsOtpLimitExceeded = false;

    public void setReauthSmsOtpLimitExceeded() {
        this.reauthSmsOtpLimitExceeded = true;
    }

    public boolean isReauthSmsOtpLimitExceeded() {
        return reauthSmsOtpLimitExceeded;
    }
}
