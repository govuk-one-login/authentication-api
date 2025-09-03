package uk.gov.di.authentication.userpermissions.entity;

import java.time.Instant;

public sealed interface Decision permits Decision.Permitted, Decision.TemporarilyLockedOut {

    int attemptCount();

    record Permitted(int attemptCount) implements Decision {}

    record TemporarilyLockedOut(
            ForbiddenReason forbiddenReason,
            int attemptCount,
            Instant lockedUntil,
            boolean isFirstTimeLimit)
            implements Decision {}
}
