package uk.gov.di.authentication.shared.tracing;

import io.lettuce.core.protocol.RedisCommand;
import io.lettuce.core.tracing.TraceContext;
import io.lettuce.core.tracing.TraceContextProvider;
import io.lettuce.core.tracing.Tracer;
import io.lettuce.core.tracing.TracerProvider;
import io.lettuce.core.tracing.Tracing;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.instrumentation.lettuce.v5_1.LettuceTelemetry;

import java.net.SocketAddress;

public class ConditionalOtelRedisTracing implements Tracing {
    private final Tracing wrappedTracing;
    private final TracerProvider tracerProvider;

    public ConditionalOtelRedisTracing(Tracing otelTracing) {
        wrappedTracing = otelTracing;
        tracerProvider =
                new ConditionalOpenTelemetryTracerProvider(wrappedTracing.getTracerProvider());
    }

    public ConditionalOtelRedisTracing() {
        this(LettuceTelemetry.create(GlobalOpenTelemetry.get()).newTracing());
    }

    public static Tracing wrap(Tracing otelTracing) {
        return new ConditionalOtelRedisTracing(otelTracing);
    }

    @Override
    public TracerProvider getTracerProvider() {
        return tracerProvider;
    }

    @Override
    public TraceContextProvider initialTraceContextProvider() {
        return wrappedTracing.initialTraceContextProvider();
    }

    @Override
    public boolean isEnabled() {
        // This is read once as lettuce starts up, otherwise this would be the simple fix!
        return wrappedTracing.isEnabled();
    }

    @Override
    public boolean includeCommandArgsInSpanTags() {
        return wrappedTracing.includeCommandArgsInSpanTags();
    }

    @Override
    public Endpoint createEndpoint(SocketAddress socketAddress) {
        return wrappedTracing.createEndpoint(socketAddress);
    }

    private static Boolean isTracingAllowed() {
        return uk.gov.di.authentication.shared.tracing.Tracing.isOtelTracingAllowed();
    }

    private static class ConditionalOpenTelemetryTracerProvider implements TracerProvider {

        Tracer conditionalOpenTelemetryTracer;

        ConditionalOpenTelemetryTracerProvider(TracerProvider wrappedProvider) {
            this.conditionalOpenTelemetryTracer =
                    new ConditionalOpenTelemetryTracer(wrappedProvider.getTracer());
        }

        @Override
        public Tracer getTracer() {
            return conditionalOpenTelemetryTracer;
        }
    }

    private static class ConditionalOpenTelemetryTracer extends Tracer {

        Tracer wrappedTracer;

        ConditionalOpenTelemetryTracer(Tracer wrappedTracer) {
            this.wrappedTracer = wrappedTracer;
        }

        @Override
        public Tracer.Span nextSpan() {
            if (isTracingAllowed()) {
                return wrappedTracer.nextSpan();
            }
            return new NoopSpan();
        }

        @Override
        public Tracer.Span nextSpan(TraceContext traceContext) {
            if (isTracingAllowed()) {
                return wrappedTracer.nextSpan(traceContext);
            }
            return new NoopSpan();
        }
    }

    private static class NoopSpan extends Tracer.Span {

        @Override
        public Tracer.Span start(RedisCommand<?, ?, ?> command) {
            return this;
        }

        @Override
        public Tracer.Span name(String name) {
            return this;
        }

        @Override
        public Tracer.Span annotate(String value) {
            return this;
        }

        @Override
        public Tracer.Span tag(String key, String value) {
            return this;
        }

        @Override
        public Tracer.Span error(Throwable throwable) {
            return this;
        }

        @Override
        public Tracer.Span remoteEndpoint(Endpoint endpoint) {
            return this;
        }

        @Override
        public void finish() {
            // Do nothing
        }
    }
}
