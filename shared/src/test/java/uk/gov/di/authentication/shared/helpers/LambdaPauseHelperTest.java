package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LambdaPauseHelperTest {

    @Test
    void shouldNotThrowWhenDurationIsZero() {
        assertDoesNotThrow(() -> LambdaPauseHelper.pauseBetweenInvocations(0));
    }

    @Test
    void shouldSleepForAtLeastSpecifiedDuration() {
        long pauseDuration = 250;

        long start = System.currentTimeMillis();
        LambdaPauseHelper.pauseBetweenInvocations(pauseDuration);
        long elapsed = System.currentTimeMillis() - start;

        assertTrue(
                elapsed >= pauseDuration,
                "Expected at least " + pauseDuration + "ms elapsed but was " + elapsed);
    }

    @Test
    void shouldSetInterruptFlagWhenInterrupted() throws InterruptedException {
        LambdaPauseHelper.pauseBetweenInvocations(0);

        Thread testThread =
                new Thread(
                        () -> {
                            Thread.currentThread().interrupt();
                            LambdaPauseHelper.pauseBetweenInvocations(10000);
                            assertTrue(Thread.currentThread().isInterrupted());
                        });
        testThread.start();
        testThread.join(5000);

        assertTrue(!testThread.isAlive(), "Thread should have completed");
    }
}
