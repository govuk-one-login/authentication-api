package uk.gov.di.authentication.shared.helpers;

import com.amazonaws.xray.AWSXRay;

import java.util.concurrent.Callable;

public class InstrumentationHelper {
    private static final boolean tracingEnabled =
            Boolean.parseBoolean(System.getenv().getOrDefault("TRACING_ENABLED", "false"));

    public static <T> T segmentedFunctionCall(String segmentName, Callable<T> callable) {
        if (tracingEnabled) {
            var subSegment = AWSXRay.beginSubsegment(segmentName);
            try {
                return callable.call();
            } catch (RuntimeException e) {
                subSegment.addException(e);
                throw e;
            } catch (Exception e) {
                subSegment.addException(e);
                throw new RuntimeException(e);
            } finally {
                AWSXRay.endSubsegment();
            }
        } else {
            try {
                return callable.call();
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    public static void addAnnotation(String key, String value) {
        if (tracingEnabled) {
            AWSXRay.getCurrentSegment().putAnnotation(key, value);
        }
    }
}
