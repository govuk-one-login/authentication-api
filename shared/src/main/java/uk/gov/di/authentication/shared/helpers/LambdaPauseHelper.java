package uk.gov.di.authentication.shared.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class LambdaPauseHelper {

    private static final Logger LOG = LogManager.getLogger(LambdaPauseHelper.class);

    private LambdaPauseHelper() {}

    public static void pauseBetweenInvocations(long pauseDurationMs) {
        try {
            if (pauseDurationMs > 0) {
                LOG.info("Pausing between Lambda invocations for: {} ms", pauseDurationMs);
                Thread.sleep(pauseDurationMs);
                LOG.info("Pause between Lambda invocations complete.");
            }
        } catch (InterruptedException e) {
            LOG.warn("Pause between Lambda invocations interrupted.");
            Thread.currentThread().interrupt();
        }
    }
}
