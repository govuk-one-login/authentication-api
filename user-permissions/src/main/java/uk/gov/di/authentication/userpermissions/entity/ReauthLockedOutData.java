package uk.gov.di.authentication.userpermissions.entity;

import uk.gov.di.authentication.shared.entity.CountType;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record ReauthLockedOutData(
        ForbiddenReason forbiddenReason,
        int attemptCount,
        Instant lockedUntil,
        boolean isFirstTimeLimit,
        Map<CountType, Integer> detailedCounts,
        List<CountType> blockedCountTypes) {}
