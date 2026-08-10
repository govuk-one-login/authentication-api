package uk.gov.di.orchestration.shared.helpers;

import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.trace.Tracer;

import java.util.concurrent.Callable;

public class InstrumentationHelper {
    private static final Tracer TRACER = GlobalOpenTelemetry.getTracer("uk.gov.di.orchestration");

    public static <T> T segmentedFunctionCall(String segmentName, Callable<T> callable) {
        var span = TRACER.spanBuilder(segmentName).startSpan();
        try {
            return callable.call();
        } catch (RuntimeException e) {
            span.recordException(e);
            throw e;
        } catch (Exception e) {
            span.recordException(e);
            throw new RuntimeException(e);
        } finally {
            span.end();
        }
    }

    public static void segmentedFunctionCall(String segmentName, Runnable runnable) {
        var span = TRACER.spanBuilder(segmentName).startSpan();
        try {
            runnable.run();
        } catch (RuntimeException e) {
            span.recordException(e);
            throw e;
        } catch (Exception e) {
            span.recordException(e);
            throw new RuntimeException(e);
        } finally {
            span.end();
        }
    }
}
