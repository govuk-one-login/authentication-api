package uk.gov.di.authentication.utils.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BulkEmailBatchPauseHelper {

    private static final Logger LOG = LogManager.getLogger(BulkEmailBatchPauseHelper.class);

    public static void pauseBetweenBatches(long pauseDurationMs) {
        try {
            if (pauseDurationMs > 0) {
                LOG.info("Bulk email batch pausing for: {} ms", pauseDurationMs);
                Thread.sleep(pauseDurationMs);
                LOG.info("Bulk email batch pause complete.");
            }
        } catch (InterruptedException e) {
            LOG.warn("Thread sleep for bulk email batch pause interrupted.");
            Thread.currentThread().interrupt();
        }
    }
}
