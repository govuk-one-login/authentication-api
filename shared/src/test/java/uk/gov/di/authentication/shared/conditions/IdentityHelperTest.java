package uk.gov.di.authentication.shared.conditions;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IdentityHelperTest {

    @Test
    void shouldReturnFalseIfIdentityNotRequired() {
        assertFalse(IdentityHelper.identityRequired(false, true, true));
    }

    @Test
    void shouldReturnTrueIfIdentityRequired() {
        assertTrue(IdentityHelper.identityRequired(true, true, true));
    }

    @Test
    void shouldReturnFalseIfIdentityIsNotEnabled() {
        assertFalse(IdentityHelper.identityRequired(true, true, false));
    }

    @Test
    void shouldReturnFalseWhenRPDoesNotSupportIdentityVerification() {
        assertFalse(IdentityHelper.identityRequired(true, false, true));
    }
}
