package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.PASSWORD;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.PASSWORD_BAD;

class Argon2HelperTest {

    @Test
    void correctPasswordShouldMatchEncodedPassword() {
        String encodedPassword = Argon2EncoderHelper.argon2Hash(PASSWORD);

        assertTrue(Argon2MatcherHelper.matchRawStringWithEncoded(PASSWORD, encodedPassword));
    }

    @Test
    void wrongPasswordShouldNotMatchEncodedPassword() {
        String encodedPassword = Argon2EncoderHelper.argon2Hash(PASSWORD);

        assertFalse(Argon2MatcherHelper.matchRawStringWithEncoded(PASSWORD_BAD, encodedPassword));
    }
}
