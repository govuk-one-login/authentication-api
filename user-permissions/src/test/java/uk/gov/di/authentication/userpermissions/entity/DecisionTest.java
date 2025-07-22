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
        Decision decision = new Decision.TemporarilyLockedOut(reason, 5, lockedUntil);

        // Then
        assertEquals(5, decision.attemptCount());
        assertEquals(reason, ((Decision.TemporarilyLockedOut) decision).forbiddenReason());
        assertEquals(lockedUntil, ((Decision.TemporarilyLockedOut) decision).lockedUntil());
    }
}
