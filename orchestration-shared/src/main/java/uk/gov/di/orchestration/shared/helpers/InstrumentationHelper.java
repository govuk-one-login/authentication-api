package uk.gov.di.orchestration.shared.helpers;

import java.util.concurrent.Callable;

public class InstrumentationHelper {

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
}
