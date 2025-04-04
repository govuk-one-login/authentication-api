package uk.gov.di.authentication.shared.helpers;

import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Scope;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.authentication.shared.tracing.AuthAttributes;

import java.util.Optional;
import java.util.concurrent.Callable;

import static io.opentelemetry.context.Context.current;
import static java.util.Objects.isNull;

@ExcludeFromGeneratedCoverageReport
public class InstrumentationHelper {
    private static final Logger LOG = LogManager.getLogger(InstrumentationHelper.class);
    private static final Tracer tracer = GlobalOpenTelemetry.getTracer("instrumentation-helper");

    private static final boolean tracingEnabled =
            Boolean.parseBoolean(System.getenv().getOrDefault("TRACING_ENABLED", "true"));

    public static <T> T segmentedFunctionCall(String segmentName, Callable<T> callable) {
        return instrument(segmentName, callable, null);
    }

    public static void segmentedFunctionCall(String segmentName, Runnable runnable) {
        instrument(segmentName, null, runnable);
    }

    private static <T> T instrument(String segmentName, Callable<T> callable, Runnable runnable) {
        Span span = null;

        if (tracingEnabled) {
            span = tracer.spanBuilder(segmentName).startSpan();
        }

        try {
            if (span != null) {
                try (Scope scope = span.makeCurrent()) {
                    return executeCall(callable, runnable);
                }
            } else {
                return executeCall(callable, runnable);
            }
        } catch (RuntimeException e) {
            recordError(span, e);
            throw e;
        } catch (Exception e) {
            recordError(span, e);
            throw new RuntimeException(e);
        } finally {
            if (span != null) {
                span.end();
            }
        }
    }

    private static <T> T executeCall(Callable<T> callable, Runnable runnable) throws Exception {
        if (callable != null) {
            return callable.call();
        } else {
            runnable.run();
            return null;
        }
    }

    private static void recordError(Span span, Exception e) {
        if (span != null) {
            span.recordException(e);
            span.setAttribute(AttributeKey.stringKey("error.type"), e.getClass().getName());
            span.setStatus(StatusCode.ERROR, e.getMessage());
        }
    }

    public static <T> void addAnnotation(final AttributeKey<T> key, final T value) {
        if (isNull(value)) {
            return;
        }
        if (tracingEnabled) {
            getCurrentSpan()
                    .ifPresentOrElse(
                            s -> s.setAttribute(key, value), InstrumentationHelper::noSpanPresent);
        }
    }

    public static void addAnnotation(final String key, final String value) {
        addAnnotation(AttributeKey.stringKey(key), value);
    }

    public static void addAnnotation(final String key, final Number value) {
        if (isNull(value)) {
            return;
        }
        if (value instanceof Double || value instanceof Float) {
            addAnnotation(AttributeKey.doubleKey(key), value.doubleValue());
        } else {
            addAnnotation(AttributeKey.longKey(key), value.longValue());
        }
    }

    public static void addAnnotation(final String key, final Boolean value) {
        addAnnotation(AttributeKey.booleanKey(key), value);
    }

    public static void addSessionIdAnnotation(final String sessionId) {
        addAnnotation(AuthAttributes.AUTH_SESSION_ID, sessionId);
    }

    public static void addOrchSessionIdAnnotation(final String orchSessionId) {
        addAnnotation(AuthAttributes.ORCH_SESSION_ID, orchSessionId);
    }

    public static void addPersistentSessionIdAnnotation(final String persistentSessionId) {
        addAnnotation(AuthAttributes.SESSION_ID, persistentSessionId);
    }

    public static void addClientSessionIdAnnotation(final String clientSessionId) {
        addAnnotation(AuthAttributes.PERSISTENT_SESSION_ID, clientSessionId);
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

    private static void noSpanPresent() {
        LOG.warn("Could not add annotations to trace as no span present");
    }
}
