package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.services.cloudwatch.CloudWatchClient;
import software.amazon.awssdk.services.cloudwatch.model.Datapoint;
import software.amazon.awssdk.services.cloudwatch.model.Dimension;
import software.amazon.awssdk.services.cloudwatch.model.GetMetricStatisticsRequest;
import software.amazon.awssdk.services.cloudwatch.model.GetMetricStatisticsResponse;
import software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.time.Instant;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.entity.Application.AUTHENTICATION;
import static uk.gov.di.authentication.entity.Application.ONE_LOGIN_HOME;

class SmsQuotaMonitorHandlerTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final CloudWatchClient cloudWatchClient = mock(CloudWatchClient.class);

    @Test
    void shouldEmitWarningWhenDomesticThresholdExceeded() {
        when(configurationService.getEnvironment()).thenReturn("test");
        when(configurationService.getDomesticSmsQuotaThreshold()).thenReturn(300000.0);
        when(configurationService.getInternationalSmsQuotaThreshold()).thenReturn(3600.0);

        var handler = new SmsQuotaMonitorHandler(configurationService, cloudWatchClient);

        when(cloudWatchClient.getMetricStatistics(any(GetMetricStatisticsRequest.class)))
                .thenReturn(createMetricResponse(300100.0))
                .thenReturn(createMetricResponse(100.0));

        handler.handleRequest(mock(ScheduledEvent.class), mock(Context.class));

        var captor = ArgumentCaptor.forClass(PutMetricDataRequest.class);
        verify(cloudWatchClient, times(2)).putMetricData(captor.capture());

        var requests = captor.getAllValues();
        assertEquals(1.0, requests.get(0).metricData().get(0).value()); // Domestic warning
        assertEquals(0.0, requests.get(1).metricData().get(0).value()); // International OK
    }

    @Test
    void shouldEmitWarningWhenInternationalThresholdExceeded() {
        when(configurationService.getEnvironment()).thenReturn("test");
        when(configurationService.getDomesticSmsQuotaThreshold()).thenReturn(300000.0);
        when(configurationService.getInternationalSmsQuotaThreshold()).thenReturn(3600.0);

        var handler = new SmsQuotaMonitorHandler(configurationService, cloudWatchClient);

        when(cloudWatchClient.getMetricStatistics(any(GetMetricStatisticsRequest.class)))
                .thenReturn(createMetricResponse(100.0))
                .thenReturn(createMetricResponse(4000.0));

        handler.handleRequest(mock(ScheduledEvent.class), mock(Context.class));

        var captor = ArgumentCaptor.forClass(PutMetricDataRequest.class);
        verify(cloudWatchClient, times(2)).putMetricData(captor.capture());

        var requests = captor.getAllValues();
        assertEquals(0.0, requests.get(0).metricData().get(0).value()); // Domestic OK
        assertEquals(1.0, requests.get(1).metricData().get(0).value()); // International warning
    }

    @Test
    void shouldUseCorrectPeriodCalculation() {
        when(configurationService.getEnvironment()).thenReturn("test");
        when(configurationService.getDomesticSmsQuotaThreshold()).thenReturn(300000.0);
        when(configurationService.getInternationalSmsQuotaThreshold()).thenReturn(3600.0);

        var handler = new SmsQuotaMonitorHandler(configurationService, cloudWatchClient);

        when(cloudWatchClient.getMetricStatistics(any(GetMetricStatisticsRequest.class)))
                .thenReturn(createMetricResponse(0.0));

        handler.handleRequest(mock(ScheduledEvent.class), mock(Context.class));

        var captor = ArgumentCaptor.forClass(GetMetricStatisticsRequest.class);
        verify(cloudWatchClient, times(4)).getMetricStatistics(captor.capture());

        // Period should be multiple of 60
        for (var request : captor.getAllValues()) {
            assertTrue(request.period() % 60 == 0, "Period must be multiple of 60 seconds");
        }
    }

    @Test
    void shouldHandleNoDataScenario() {
        when(configurationService.getEnvironment()).thenReturn("test");
        when(configurationService.getDomesticSmsQuotaThreshold()).thenReturn(300000.0);
        when(configurationService.getInternationalSmsQuotaThreshold()).thenReturn(3600.0);

        var handler = new SmsQuotaMonitorHandler(configurationService, cloudWatchClient);

        when(cloudWatchClient.getMetricStatistics(any(GetMetricStatisticsRequest.class)))
                .thenReturn(createEmptyMetricResponse());

        handler.handleRequest(mock(ScheduledEvent.class), mock(Context.class));

        var captor = ArgumentCaptor.forClass(PutMetricDataRequest.class);
        verify(cloudWatchClient, times(2)).putMetricData(captor.capture());

        // Should emit 0.0 when no data available
        var requests = captor.getAllValues();
        assertEquals(0.0, requests.get(0).metricData().get(0).value());
        assertEquals(0.0, requests.get(1).metricData().get(0).value());
    }

    @Test
    void shouldUseCorrectMetricNamesAndDimensions() {
        var smsSentMetricProducer = "production-email-notification-sqs-lambda";
        var accountManagementSmsSentMetricProducer = "production-account-management-sqs-lambda";

        when(configurationService.getEnvironment()).thenReturn("production");
        when(configurationService.getEmailSqsLambdaFunctionName())
                .thenReturn(smsSentMetricProducer);
        when(configurationService.getAccountManagementSqsLambdaFunctionName())
                .thenReturn(accountManagementSmsSentMetricProducer);
        when(configurationService.getDomesticSmsQuotaThreshold()).thenReturn(300000.0);
        when(configurationService.getInternationalSmsQuotaThreshold()).thenReturn(3600.0);

        var handler = new SmsQuotaMonitorHandler(configurationService, cloudWatchClient);
        when(cloudWatchClient.getMetricStatistics(any(GetMetricStatisticsRequest.class)))
                .thenReturn(createMetricResponse(0.0));

        handler.handleRequest(mock(ScheduledEvent.class), mock(Context.class));

        var getCaptor = ArgumentCaptor.forClass(GetMetricStatisticsRequest.class);
        verify(cloudWatchClient, times(4)).getMetricStatistics(getCaptor.capture());

        var requests = getCaptor.getAllValues();

        // Group requests by metric name, application, and "metric producer".
        var domesticAuthRequests =
                requests.stream()
                        .filter(r -> "DomesticSmsSent".equals(r.metricName()))
                        .filter(r -> hasApplicationDimension(r, AUTHENTICATION.getValue()))
                        .filter(r -> hasProducerDimensions(r, smsSentMetricProducer))
                        .toList();

        var domesticHomeRequests =
                requests.stream()
                        .filter(r -> "DomesticSmsSent".equals(r.metricName()))
                        .filter(r -> hasApplicationDimension(r, ONE_LOGIN_HOME.getValue()))
                        .filter(
                                r ->
                                        hasProducerDimensions(
                                                r, accountManagementSmsSentMetricProducer))
                        .toList();

        var internationalAuthRequests =
                requests.stream()
                        .filter(r -> "InternationalSmsSent".equals(r.metricName()))
                        .filter(r -> hasApplicationDimension(r, AUTHENTICATION.getValue()))
                        .filter(r -> hasProducerDimensions(r, smsSentMetricProducer))
                        .toList();

        var internationalHomeRequests =
                requests.stream()
                        .filter(r -> "InternationalSmsSent".equals(r.metricName()))
                        .filter(r -> hasApplicationDimension(r, ONE_LOGIN_HOME.getValue()))
                        .filter(
                                r ->
                                        hasProducerDimensions(
                                                r, accountManagementSmsSentMetricProducer))
                        .toList();

        // Verify we have exactly one of each type
        assertEquals(1, domesticAuthRequests.size());
        assertEquals(1, domesticHomeRequests.size());
        assertEquals(1, internationalAuthRequests.size());
        assertEquals(1, internationalHomeRequests.size());

        // Verify common dimensions for all requests
        requests.forEach(
                request -> {
                    assertDimensionEquals(request, "Environment", "production");
                    assertDimensionEquals(request, "ServiceType", "AWS::Lambda::Function");
                });
    }

    private boolean hasApplicationDimension(
            GetMetricStatisticsRequest request, String applicationValue) {
        return request.dimensions().stream()
                .anyMatch(
                        dim ->
                                "Application".equals(dim.name())
                                        && applicationValue.equals(dim.value()));
    }

    private boolean hasProducerDimensions(
            GetMetricStatisticsRequest request, String producerValue) {
        boolean hasLogGroup =
                request.dimensions().stream()
                        .anyMatch(
                                dim ->
                                        "LogGroup".equals(dim.name())
                                                && producerValue.equals(dim.value()));

        boolean hasServiceName =
                request.dimensions().stream()
                        .anyMatch(
                                dim ->
                                        "ServiceName".equals(dim.name())
                                                && producerValue.equals(dim.value()));

        return hasLogGroup && hasServiceName;
    }

    private void assertDimensionEquals(
            GetMetricStatisticsRequest request, String dimensionName, String expectedValue) {
        String actualValue =
                request.dimensions().stream()
                        .filter(dim -> dimensionName.equals(dim.name()))
                        .findFirst()
                        .map(Dimension::value)
                        .orElseThrow(
                                () ->
                                        new AssertionError(
                                                String.format(
                                                        "Dimension '%s' not found",
                                                        dimensionName)));

        assertEquals(
                expectedValue,
                actualValue,
                String.format("Dimension '%s' should be %s", dimensionName, expectedValue));
    }

    private GetMetricStatisticsResponse createMetricResponse(double value) {
        return GetMetricStatisticsResponse.builder()
                .datapoints(
                        List.of(Datapoint.builder().sum(value).timestamp(Instant.now()).build()))
                .build();
    }

    private GetMetricStatisticsResponse createEmptyMetricResponse() {
        return GetMetricStatisticsResponse.builder().datapoints(Collections.emptyList()).build();
    }
}
