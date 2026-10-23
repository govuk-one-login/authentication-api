package uk.gov.di.authentication.shared.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class LambdaPauseHelper {

    private static final Logger LOG = LogManager.getLogger(LambdaPauseHelper.class);

    private LambdaPauseHelper() {}

    public static void pause(long millis) {
        if (millis <= 0) {
            return;
        }

        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public static void pauseBetweenInvocations(long pauseDurationMs) {
        if (pauseDurationMs > 0) {
            LOG.info("Pausing between Lambda invocations for: {} ms", pauseDurationMs);
            pause(pauseDurationMs);
            LOG.info("Pause between Lambda invocations complete.");
        }
    }
}
