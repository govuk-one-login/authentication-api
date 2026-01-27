package uk.gov.di.authentication.userpermissions.entity;

import uk.gov.di.authentication.shared.entity.CountType;

import java.time.Instant;
import java.util.Map;

public sealed interface Decision
        permits Decision.Permitted, Decision.TemporarilyLockedOut, Decision.IndefinitelyLockedOut, Decision.ReauthLockedOut {

    int attemptCount();

    record Permitted(int attemptCount) implements Decision {}

    record TemporarilyLockedOut(
            ForbiddenReason forbiddenReason,
            int attemptCount,
            Instant lockedUntil,
            boolean isFirstTimeLimit)
            implements Decision {}

    record IndefinitelyLockedOut(
            ForbiddenReason forbiddenReason,
            int attemptCount)
            implements Decision {}

    record ReauthLockedOut(
            ForbiddenReason forbiddenReason,
            int attemptCount,
            Instant lockedUntil,
            boolean isFirstTimeLimit,
            Map<CountType, Integer> detailedCounts,
            java.util.List<CountType> blockedCountTypes)
            implements Decision {}
}
