package uk.gov.di.authentication.userpermissions.entity;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DecisionTest {

    @Test
    void shouldCreatePermittedDecision() {
        // When
        Decision decision = new Decision.Permitted(3);

        // Then
        assertEquals(3, decision.attemptCount());
    }

    @Test
    void shouldCreateTemporarilyLockedOutDecision() {
        // Given
        ForbiddenReason reason = ForbiddenReason.EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT;
        Instant lockedUntil = Instant.now().plusSeconds(300);

        // When
        Decision decision = new Decision.TemporarilyLockedOut(reason, 5, lockedUntil, false);

        // Then
        assertEquals(5, decision.attemptCount());
        assertEquals(reason, ((Decision.TemporarilyLockedOut) decision).forbiddenReason());
        assertEquals(lockedUntil, ((Decision.TemporarilyLockedOut) decision).lockedUntil());
        assertEquals(false, ((Decision.TemporarilyLockedOut) decision).isFirstTimeLimit());
    }

    @Test
    void shouldCreateTemporarilyLockedOutDecisionWithFirstTimeLimit() {
        // Given
        ForbiddenReason reason = ForbiddenReason.EXCEEDED_SEND_EMAIL_OTP_NOTIFICATION_LIMIT;
        Instant lockedUntil = Instant.now().plusSeconds(300);

        // When
        Decision decision = new Decision.TemporarilyLockedOut(reason, 5, lockedUntil, true);

        // Then
        assertEquals(5, decision.attemptCount());
        assertEquals(reason, ((Decision.TemporarilyLockedOut) decision).forbiddenReason());
        assertEquals(lockedUntil, ((Decision.TemporarilyLockedOut) decision).lockedUntil());
        assertEquals(true, ((Decision.TemporarilyLockedOut) decision).isFirstTimeLimit());
    }

    @Test
    void shouldCreateIndefinitelyLockedOutDecision() {
        // Given
        ForbiddenReason reason = ForbiddenReason.EXCEEDED_SEND_EMAIL_OTP_NOTIFICATION_LIMIT;

        // When
        var decision = new Decision.IndefinitelyLockedOut(reason, 5);

        // Then
        assertEquals(reason, decision.forbiddenReason());
        assertEquals(5, decision.attemptCount());
    }
}
