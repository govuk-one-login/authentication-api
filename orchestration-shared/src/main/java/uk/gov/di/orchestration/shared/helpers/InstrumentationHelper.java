package uk.gov.di.orchestration.shared.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.concurrent.Callable;

public class InstrumentationHelper {
    private static final Logger LOG = LogManager.getLogger(InstrumentationHelper.class);

    public static <T> T segmentedFunctionCall(String segmentName, Callable<T> callable) {
        try {
            return callable.call();
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void segmentedFunctionCall(String segmentName, Runnable runnable) {
        runnable.run();
    }

    public static void addAnnotation(final String key, final String value) {}

    public static void addAnnotation(final String key, final Number value) {}

    public static void addAnnotation(final String key, final Boolean value) {}

    private static void noSubSegmentPresent() {
        LOG.warn("Could not add annotations to trace as no subsegment present");
    }
}
