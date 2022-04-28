package uk.gov.di.authentication.shared.helpers;

import com.amazonaws.xray.AWSXRay;

import java.util.Optional;
import java.util.concurrent.Callable;

public class InstrumentationHelper {
    private static final boolean tracingEnabled =
            Boolean.parseBoolean(System.getenv().getOrDefault("TRACING_ENABLED", "false"));

    public static <T> T segmentedFunctionCall(String segmentName, Callable<T> callable) {
        if (tracingEnabled) {
            var segment = Optional.of(AWSXRay.beginSubsegment(segmentName));
            try {
                return callable.call();
            } catch (Exception e) {
                segment.ifPresent(s -> s.addException(e));
                throw new RuntimeException(e);
            } finally {
                AWSXRay.endSegment();
            }
        } else {
            try {
                return callable.call();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }
}
