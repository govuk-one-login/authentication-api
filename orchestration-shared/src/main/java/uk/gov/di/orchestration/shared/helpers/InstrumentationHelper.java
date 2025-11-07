package uk.gov.di.orchestration.shared.helpers;

import com.amazonaws.xray.AWSXRay;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.concurrent.Callable;

import static java.util.Objects.nonNull;

public class InstrumentationHelper {
    private static final Logger LOG = LogManager.getLogger(InstrumentationHelper.class);

    public static <T> T segmentedFunctionCall(String segmentName, Callable<T> callable) {
        if (false) {
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

    public static void segmentedFunctionCall(String segmentName, Runnable runnable) {
        if (false) {
            var subSegment = AWSXRay.beginSubsegment(segmentName);
            try {
                runnable.run();
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
            runnable.run();
        }
    }

    public static void addAnnotation(final String key, final String value) {
        if (false && nonNull(value)) {
            AWSXRay.getCurrentSubsegmentOptional()
                    .ifPresentOrElse(
                            s -> s.putAnnotation(key, value),
                            InstrumentationHelper::noSubSegmentPresent);
        }
    }

    public static void addAnnotation(final String key, final Number value) {
        if (false && nonNull(value)) {
            AWSXRay.getCurrentSubsegmentOptional()
                    .ifPresentOrElse(
                            s -> s.putAnnotation(key, value),
                            InstrumentationHelper::noSubSegmentPresent);
        }
    }

    public static void addAnnotation(final String key, final Boolean value) {
        if (false && nonNull(value)) {
            AWSXRay.getCurrentSubsegmentOptional()
                    .ifPresentOrElse(
                            s -> s.putAnnotation(key, value),
                            InstrumentationHelper::noSubSegmentPresent);
        }
    }

    private static void noSubSegmentPresent() {
        LOG.warn("Could not add annotations to trace as no subsegment present");
    }
}
