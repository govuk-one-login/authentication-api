package uk.gov.di.authentication.userpermissions.entity;

import uk.gov.di.authentication.shared.entity.CountType;

import java.time.Instant;
import java.util.Map;

public sealed interface Decision permits Decision.PermittedDecision, Decision.DeniedDecision {
    ////// DECISION

    boolean isPermitted();

    sealed interface PermittedDecision extends Decision {
        @Override
        default boolean isPermitted() {
            return true;
        }
    }

    record Permitted() implements PermittedDecision {}

    sealed interface DeniedDecision extends Decision {
        @Override
        default boolean isPermitted() {
            return false;
        }

        ForbiddenReason forbiddenReason();
    }

    record Denied(ForbiddenReason forbiddenReason) implements DeniedDecision {}

    ////// LOCKOUT DECISION

    sealed interface LockoutDecision
            permits NotLockedOut, TemporarilyLockedOut, IndefinitelyLockedOut, ReauthLockedOut {
        int attemptCount();
    }

    record NotLockedOut(int attemptCount) implements PermittedDecision, LockoutDecision {}

    record TemporarilyLockedOut(
            ForbiddenReason forbiddenReason,
            int attemptCount,
            Instant lockedUntil,
            boolean isFirstTimeLimit)
            implements DeniedDecision, LockoutDecision {}

    record IndefinitelyLockedOut(ForbiddenReason forbiddenReason, int attemptCount)
            implements DeniedDecision, LockoutDecision {}

    record ReauthLockedOut(
            ForbiddenReason forbiddenReason,
            int attemptCount,
            Instant lockedUntil,
            boolean isFirstTimeLimit,
            Map<CountType, Integer> detailedCounts,
            java.util.List<CountType> blockedCountTypes)
            implements DeniedDecision, LockoutDecision {}
}
