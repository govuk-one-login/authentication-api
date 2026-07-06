package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Argon2MatcherHelperExtractParametersTest {

    private static final String HASH_M15360_T2_P1 =
            "$argon2id$v=19$m=15360,t=2,p=1$c29tZXNhbHRieXRlcw$dGVzdGhhc2hieXRlcw";

    private static final String HASH_M32768_T3_P4 =
            "$argon2id$v=19$m=32768,t=3,p=4$c29tZXNhbHRieXRlcw$dGVzdGhhc2hieXRlcw";

    @Test
    void shouldExtractParametersFromValidHash() {
        Optional<Argon2HashParameters> result =
                Argon2MatcherHelper.extractParameters(HASH_M15360_T2_P1);

        assertTrue(result.isPresent());
        assertEquals(15360, result.get().memory());
        assertEquals(2, result.get().iterations());
        assertEquals(1, result.get().parallelism());
    }

    @Test
    void shouldExtractDifferentParametersFromValidHash() {
        Optional<Argon2HashParameters> result =
                Argon2MatcherHelper.extractParameters(HASH_M32768_T3_P4);

        assertTrue(result.isPresent());
        assertEquals(32768, result.get().memory());
        assertEquals(3, result.get().iterations());
        assertEquals(4, result.get().parallelism());
    }

    @ParameterizedTest
    @ValueSource(strings = {"not-a-valid-hash", "", "$$$"})
    void shouldReturnEmptyForInvalidInput(String invalidHash) {
        Optional<Argon2HashParameters> result = Argon2MatcherHelper.extractParameters(invalidHash);

        assertTrue(result.isEmpty());
    }
}
