package uk.gov.di.orchestration.shared.helpers;

import com.amazonaws.xray.AWSXRay;
import com.amazonaws.xray.entities.Subsegment;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.concurrent.Callable;

import static java.util.Objects.nonNull;

@ExcludeFromGeneratedCoverageReport
public class InstrumentationHelper {
    private static final Logger LOG = LogManager.getLogger(InstrumentationHelper.class);
    private static final Tracer tracer = GlobalOpenTelemetry.getTracer("instrumentation-helper");

    private static final boolean TRACING_ENABLED = false;

    private static void recordException(Span span, Subsegment subSegment, Exception e) {
        span.recordException(e);
        span.setAttribute(AttributeKey.stringKey("error.type"), e.getClass().getName());
        span.setStatus(StatusCode.ERROR, e.getMessage());

        subSegment.addException(e);
    }

    public static <T> T segmentedFunctionCall(String segmentName, Callable<T> callable) {
        if (TRACING_ENABLED) {
            Span span = tracer.spanBuilder(segmentName).startSpan();
            var subSegment = AWSXRay.beginSubsegment(segmentName);
            try {
                return callable.call();
            } catch (RuntimeException e) {
                recordException(span, subSegment, e);
                throw e;
            } catch (Exception e) {
                recordException(span, subSegment, e);
                throw new RuntimeException(e);
            } finally {
                span.end();
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
        if (TRACING_ENABLED) {
            Span span = tracer.spanBuilder(segmentName).startSpan();
            var subSegment = AWSXRay.beginSubsegment(segmentName);
            try {
                runnable.run();
            } catch (RuntimeException e) {
                recordException(span, subSegment, e);
                throw e;
            } catch (Exception e) {
                recordException(span, subSegment, e);
                throw new RuntimeException(e);
            } finally {
                span.end();
                AWSXRay.endSubsegment();
            }
        } else {
            runnable.run();
        }
    }

    public static void addAnnotation(final String key, final String value) {
        if (TRACING_ENABLED && nonNull(value)) {
            AWSXRay.getCurrentSubsegmentOptional()
                    .ifPresentOrElse(
                            s -> s.putAnnotation(key, value),
                            InstrumentationHelper::noSubSegmentPresent);
        }
    }

    public static void addAnnotation(final String key, final Number value) {
        if (TRACING_ENABLED && nonNull(value)) {
            AWSXRay.getCurrentSubsegmentOptional()
                    .ifPresentOrElse(
                            s -> s.putAnnotation(key, value),
                            InstrumentationHelper::noSubSegmentPresent);
        }
    }

    public static void addAnnotation(final String key, final Boolean value) {
        if (TRACING_ENABLED && nonNull(value)) {
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
