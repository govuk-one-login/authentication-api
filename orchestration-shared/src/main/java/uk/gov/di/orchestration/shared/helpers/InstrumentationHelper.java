package uk.gov.di.orchestration.shared.helpers;

import com.amazonaws.xray.AWSXRay;
import com.amazonaws.xray.entities.Subsegment;
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
import static java.util.Objects.nonNull;

@ExcludeFromGeneratedCoverageReport
public class InstrumentationHelper {
    private static final Logger LOG = LogManager.getLogger(InstrumentationHelper.class);
    private static final Tracer tracer = GlobalOpenTelemetry.getTracer("instrumentation-helper");

    private static final boolean TRACING_ENABLED = false;

    public static <T> T instrumentedFunctionCall(String segmentName, Callable<T> callable) {
        if (TRACING_ENABLED) {
            Span span = tracer.spanBuilder(segmentName).startSpan();
            var subSegment = AWSXRay.beginSubsegment(segmentName);
            try {
                try (Scope callableScope = span.makeCurrent()) {
                    return callable.call();
                } catch (RuntimeException e) {
                    recordException(span, subSegment, e);
                    throw e;
                } catch (Exception e) {
                    recordException(span, subSegment, e);
                    throw new RuntimeException(e);
                }
            } finally {
                AWSXRay.endSubsegment();
                span.end();
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

    public static void instrumentedFunctionCall(String segmentName, Runnable runnable) {
        if (TRACING_ENABLED) {
            Span span = tracer.spanBuilder(segmentName).startSpan();
            var subSegment = AWSXRay.beginSubsegment(segmentName);
            try {
                try (Scope runnableScope = span.makeCurrent()) {
                    runnable.run();
                } catch (RuntimeException e) {
                    recordException(span, subSegment, e);
                    throw e;
                } catch (Exception e) {
                    recordException(span, subSegment, e);
                    throw new RuntimeException(e);
                }
            } finally {
                AWSXRay.endSubsegment();
                span.end();
            }
        } else {
            runnable.run();
        }
    }

    private static void recordException(Span span, Subsegment subSegment, Exception e) {
        span.recordException(e);
        span.setAttribute(AttributeKey.stringKey("error.type"), e.getClass().getName());
        span.setStatus(StatusCode.ERROR, e.getMessage());

        subSegment.addException(e);
    }

    @SuppressWarnings("unused")
    public static void addAnnotation(final AttributeKey<String> key, final String value) {
        if (TRACING_ENABLED && nonNull(value)) {
            AWSXRay.getCurrentSubsegmentOptional()
                    .ifPresentOrElse(
                            s -> s.putAnnotation(key.getKey(), value),
                            InstrumentationHelper::noSubSegmentPresent);
            getCurrentSpan()
                    .ifPresentOrElse(
                            s -> s.setAttribute(key, value), InstrumentationHelper::noSpanPresent);
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
