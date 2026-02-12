package uk.gov.di.authentication.userpermissions.entity;

import java.time.Instant;

public record TemporarilyLockedOutData(
        ForbiddenReason forbiddenReason,
        int attemptCount,
        Instant lockedUntil,
        boolean isFirstTimeLimit) {}
