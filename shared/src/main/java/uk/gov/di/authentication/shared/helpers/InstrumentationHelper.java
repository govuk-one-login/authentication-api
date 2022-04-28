package uk.gov.di.authentication.shared.helpers;

import com.amazonaws.xray.AWSXRay;

import java.util.concurrent.Callable;

public class InstrumentationHelper {
    private static final boolean tracingEnabled =
            Boolean.parseBoolean(System.getenv().getOrDefault("TRACING_ENABLED", "false"));

    public static <T> T segmentedFunctionCall(String segmentName, Callable<T> callable) {
        if (tracingEnabled) {
            var segment = AWSXRay.beginSubsegment(segmentName);
            try {
                return callable.call();
            } catch (RuntimeException e) {
                segment.addException(e);
                throw e;
            } catch (Exception e) {
                segment.addException(e);
                throw new RuntimeException(e);
            } finally {
                AWSXRay.endSegment();
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
}
