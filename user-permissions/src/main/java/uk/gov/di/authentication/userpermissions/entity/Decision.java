package uk.gov.di.authentication.userpermissions.entity;

import uk.gov.di.authentication.shared.entity.CountType;

import java.time.Instant;
import java.util.Map;

public sealed interface Decision
        permits Decision.Permitted, Decision.TemporarilyLockedOut, Decision.ReauthLockedOut {

    int attemptCount();

    record Permitted(int attemptCount) implements Decision {}

    record TemporarilyLockedOut(
            ForbiddenReason forbiddenReason,
            int attemptCount,
            Instant lockedUntil,
            boolean isFirstTimeLimit)
            implements Decision {}

    record ReauthLockedOut(
            ForbiddenReason forbiddenReason,
            int attemptCount,
            Instant lockedUntil,
            boolean isFirstTimeLimit,
            Map<CountType, Integer> detailedCounts)
            implements Decision {}
}
