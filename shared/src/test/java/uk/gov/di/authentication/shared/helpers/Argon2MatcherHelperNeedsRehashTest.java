package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class Argon2MatcherHelperNeedsRehashTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    private static final String HASH_M15360_T2_P1 =
            "$argon2id$v=19$m=15360,t=2,p=1$c29tZXNhbHRieXRlcw$dGVzdGhhc2hieXRlcw";

    @Test
    void shouldReturnFalseWhenAllParamsMatchConfig() {
        setupConfig(15360, 2, 1);
        assertFalse(Argon2MatcherHelper.needsRehash(HASH_M15360_T2_P1, configurationService));
    }

    @Test
    void shouldReturnTrueWhenMemoryDiffers() {
        setupConfig(7777, 2, 1);
        assertTrue(Argon2MatcherHelper.needsRehash(HASH_M15360_T2_P1, configurationService));
    }

    @Test
    void shouldReturnTrueWhenIterationsDiffer() {
        setupConfig(15360, 7, 1);
        assertTrue(Argon2MatcherHelper.needsRehash(HASH_M15360_T2_P1, configurationService));
    }

    @Test
    void shouldReturnTrueWhenParallelismDiffers() {
        setupConfig(15360, 2, 7);
        assertTrue(Argon2MatcherHelper.needsRehash(HASH_M15360_T2_P1, configurationService));
    }

    @Test
    void shouldReturnTrueWhenVersionDiffers() {
        String hashWithOldVersion =
                "$argon2id$v=16$m=15360,t=2,p=1$c29tZXNhbHRieXRlcw$dGVzdGhhc2hieXRlcw";
        setupConfig(15360, 2, 1);
        assertTrue(Argon2MatcherHelper.needsRehash(hashWithOldVersion, configurationService));
    }

    @Test
    void shouldReturnFalseForMalformedHash() {
        setupConfig(15360, 2, 1);
        assertFalse(Argon2MatcherHelper.needsRehash("not-a-valid-hash", configurationService));
    }

    @Test
    void shouldReturnFalseForEmptyString() {
        setupConfig(15360, 2, 1);
        assertFalse(Argon2MatcherHelper.needsRehash("", configurationService));
    }

    private void setupConfig(int memory, int iterations, int parallelism) {
        when(configurationService.getArgon2MemoryInKibibytes()).thenReturn(memory);
        when(configurationService.getArgon2Iterations()).thenReturn(iterations);
        when(configurationService.getArgon2Parallelism()).thenReturn(parallelism);
    }
}
