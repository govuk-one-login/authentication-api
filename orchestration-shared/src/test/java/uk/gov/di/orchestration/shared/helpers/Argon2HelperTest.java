package uk.gov.di.orchestration.shared.helpers;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;

class Argon2HelperTest {

    @Test
    void correctPasswordShouldMatchEncodedPassword() {
        String testPassword = "test-password123";
        String encodedPassword = Argon2EncoderHelper.argon2Hash(testPassword);

        Assertions.assertTrue(
                Argon2MatcherHelper.matchRawStringWithEncoded(testPassword, encodedPassword));
    }

    @Test
    void wrongPasswordShouldNotMatchEncodedPassword() {
        String testPassword = "test-password123";
        String wrongPassword = "test-password";
        String encodedPassword = Argon2EncoderHelper.argon2Hash(testPassword);

        assertFalse(Argon2MatcherHelper.matchRawStringWithEncoded(wrongPassword, encodedPassword));
    }
}
