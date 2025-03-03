package uk.gov.di.authentication.shared.tracing;

import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.instrumentation.awssdk.v2_2.AwsSdkTelemetry;
import software.amazon.awssdk.core.SdkRequest;
import software.amazon.awssdk.core.interceptor.Context;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.http.SdkHttpRequest;
import software.amazon.awssdk.services.sqs.SqsClient;

import java.io.InputStream;
import java.util.Optional;

public class ConditionalOtelTracingExecutionInterceptor implements ExecutionInterceptor {

    private final AwsSdkTelemetry telemetry;
    private final ExecutionInterceptor wrappedInterceptor;

    private Boolean isInterceptionAllowed() {
        return Tracing.isOtelTracingAllowed();
    }

    public ConditionalOtelTracingExecutionInterceptor() {
        this.telemetry = AwsSdkTelemetry.create(GlobalOpenTelemetry.get());
        this.wrappedInterceptor = telemetry.newExecutionInterceptor();
    }

    public SqsClient wrap(SqsClient sqsClient) {
        return telemetry.wrap(sqsClient);
    }

    @Override
    public SdkRequest modifyRequest(
            Context.ModifyRequest context, ExecutionAttributes executionAttributes) {

        if (isInterceptionAllowed()) {
            return wrappedInterceptor.modifyRequest(context, executionAttributes);
        }
        return context.request();
    }

    @Override
    public void beforeTransmission(
            Context.BeforeTransmission context, ExecutionAttributes executionAttributes) {
        if (isInterceptionAllowed()) {
            wrappedInterceptor.beforeTransmission(context, executionAttributes);
        }
    }

    @Override
    public SdkHttpRequest modifyHttpRequest(
            Context.ModifyHttpRequest context, ExecutionAttributes executionAttributes) {
        if (isInterceptionAllowed()) {
            return wrappedInterceptor.modifyHttpRequest(context, executionAttributes);
        }
        return context.httpRequest();
    }

    @Override
    public Optional<InputStream> modifyHttpResponseContent(
            Context.ModifyHttpResponse context, ExecutionAttributes executionAttributes) {
        if (isInterceptionAllowed()) {
            return wrappedInterceptor.modifyHttpResponseContent(context, executionAttributes);
        }
        return Optional.empty();
    }

    @Override
    public void afterExecution(
            Context.AfterExecution context, ExecutionAttributes executionAttributes) {
        if (isInterceptionAllowed()) {
            wrappedInterceptor.afterExecution(context, executionAttributes);
        }
    }

    @Override
    public void onExecutionFailure(
            Context.FailedExecution context, ExecutionAttributes executionAttributes) {
        if (isInterceptionAllowed()) {
            wrappedInterceptor.onExecutionFailure(context, executionAttributes);
        }
    }
}
