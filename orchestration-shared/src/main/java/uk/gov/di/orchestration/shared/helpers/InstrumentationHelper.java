package uk.gov.di.orchestration.shared.helpers;

import com.amazonaws.xray.AWSXRay;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Scope;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.orchestration.shared.tracing.AuthAttributes;

import java.util.Optional;
import java.util.concurrent.Callable;

import static io.opentelemetry.context.Context.current;
import static java.util.Objects.isNull;
import static uk.gov.di.orchestration.shared.tracing.Tracing.TRACING_ENABLED;
import static uk.gov.di.orchestration.shared.tracing.Tracing.isOtelTracingAllowed;

@ExcludeFromGeneratedCoverageReport
public class InstrumentationHelper {
    private static final Logger LOG = LogManager.getLogger(InstrumentationHelper.class);
    private static final Tracer tracer = GlobalOpenTelemetry.getTracer("instrumentation-helper");

    private static <T> T otelAndXrayInstrumentedFunctionCall(
            String segmentName, Callable<T> callable) {
        Span span = tracer.spanBuilder(segmentName).startSpan();
        var subSegment = AWSXRay.beginSubsegment(segmentName);
        try {
            try (Scope callableScope = span.makeCurrent()) {
                return callable.call();
            } catch (RuntimeException e) {
                recordExceptionOnSpan(span, e);
                subSegment.addException(e);
                throw e;
            } catch (Exception e) {
                recordExceptionOnSpan(span, e);
                subSegment.addException(e);
                throw new RuntimeException(e);
            }
        } finally {
            AWSXRay.endSubsegment();
            span.end();
        }
    }

    public static <T> T instrumentedFunctionCall(String segmentName, Callable<T> callable) {
        if (isOtelTracingAllowed()) {
            // If we are within a handler, we can create spans and subsegments
            return otelAndXrayInstrumentedFunctionCall(segmentName, callable);
        } else if (TRACING_ENABLED) {
            // If we are not within a handler, we can create subsegments
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

    public static void otelAndXrayInstrumentedFunctionCall(String segmentName, Runnable runnable) {
        Span span = tracer.spanBuilder(segmentName).startSpan();
        var subSegment = AWSXRay.beginSubsegment(segmentName);
        try {
            try (Scope runnableScope = span.makeCurrent()) {
                runnable.run();
            } catch (RuntimeException e) {
                recordExceptionOnSpan(span, e);
                subSegment.addException(e);
                throw e;
            } catch (Exception e) {
                recordExceptionOnSpan(span, e);
                subSegment.addException(e);
                throw new RuntimeException(e);
            }
        } finally {
            AWSXRay.endSubsegment();
            span.end();
        }
    }

    public static void instrumentedFunctionCall(String segmentName, Runnable runnable) {
        if (isOtelTracingAllowed()) {
            otelAndXrayInstrumentedFunctionCall(segmentName, runnable);
        } else if (TRACING_ENABLED) {
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

    private static void recordExceptionOnSpan(Span span, Exception e) {
        span.recordException(e);
        span.setAttribute(AttributeKey.stringKey("error.type"), e.getClass().getName());
        span.setStatus(StatusCode.ERROR, e.getMessage());
    }

    public static void addAnnotation(final String key, final String value) {
        addAnnotation(AttributeKey.stringKey(key), value);
    }

    public static void addAnnotation(final AttributeKey<String> key, final String value) {
        if (isNull(value)) {
            return;
        }
        if (isOtelTracingAllowed()) {
            getCurrentSpan()
                    .ifPresentOrElse(
                            s -> s.setAttribute(key, value), InstrumentationHelper::noSpanPresent);
        }
        if (TRACING_ENABLED) {
            AWSXRay.getCurrentSubsegmentOptional()
                    .ifPresentOrElse(
                            s -> s.putAnnotation(key.getKey(), value),
                            InstrumentationHelper::noSubSegmentPresent);
        }
    }

    public static void addSessionIdAnnotation(final String sessionId) {
        addAnnotation(AuthAttributes.AUTH_SESSION_ID, sessionId);
    }

    public static void addAuthSessionIdAnnotation(final String authSessionId) {
        addAnnotation(AuthAttributes.PERSISTENT_SESSION_ID, authSessionId);
    }

    public static void addPersistentSessionIdAnnotation(final String persistentSessionId) {
        addAnnotation(AuthAttributes.SESSION_ID, persistentSessionId);
    }

    public static void addClientIdAnnotation(final String clientId) {
        addAnnotation(AuthAttributes.CLIENT_ID, clientId);
    }

    private static Optional<Span> getCurrentSpan() {
        Span span = Span.fromContext(current());
        if (span.getSpanContext().isValid()) {
            return Optional.of(span);
        }
        return Optional.empty();
    }

    private static void noSubSegmentPresent() {
        LOG.warn("Could not add annotations to trace as no subsegment present");
    }

    private static void noSpanPresent() {
        LOG.warn("Could not add annotations to trace as no span present");
    }
}
