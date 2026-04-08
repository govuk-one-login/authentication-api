package uk.gov.di.authentication.utils.helpers;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BulkEmailBatchPauseHelperTest {

    @Test
    void shouldNotThrowWhenDurationIsZero() {
        assertDoesNotThrow(() -> BulkEmailBatchPauseHelper.pauseBetweenBatches(0));
    }

    @Test
    void shouldSleepForAtLeastSpecifiedDuration() {
        long pauseDuration = 250;

        long start = System.currentTimeMillis();
        BulkEmailBatchPauseHelper.pauseBetweenBatches(pauseDuration);
        long elapsed = System.currentTimeMillis() - start;
        assertTrue(
                elapsed >= pauseDuration,
                "Expected at least " + pauseDuration + "ms elapsed but was " + elapsed);
    }
}
