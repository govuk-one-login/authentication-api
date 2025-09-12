package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.services.cloudwatch.CloudWatchClient;
import software.amazon.awssdk.services.cloudwatch.model.Datapoint;
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
        verify(cloudWatchClient, times(2)).getMetricStatistics(captor.capture());

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
        when(configurationService.getEnvironment()).thenReturn("production");
        when(configurationService.getDomesticSmsQuotaThreshold()).thenReturn(300000.0);
        when(configurationService.getInternationalSmsQuotaThreshold()).thenReturn(3600.0);

        var handler = new SmsQuotaMonitorHandler(configurationService, cloudWatchClient);

        when(cloudWatchClient.getMetricStatistics(any(GetMetricStatisticsRequest.class)))
                .thenReturn(createMetricResponse(0.0));

        handler.handleRequest(mock(ScheduledEvent.class), mock(Context.class));

        var getCaptor = ArgumentCaptor.forClass(GetMetricStatisticsRequest.class);
        var putCaptor = ArgumentCaptor.forClass(PutMetricDataRequest.class);
        verify(cloudWatchClient, times(2)).getMetricStatistics(getCaptor.capture());
        verify(cloudWatchClient, times(2)).putMetricData(putCaptor.capture());

        // Verify input metric names
        var getRequests = getCaptor.getAllValues();
        assertEquals("DomesticSmsSent", getRequests.get(0).metricName());
        assertEquals("InternationalSmsSent", getRequests.get(1).metricName());

        // Verify output metric names
        var putRequests = putCaptor.getAllValues();
        assertEquals(
                "DomesticSmsQuotaEarlyWarning",
                putRequests.get(0).metricData().get(0).metricName());
        assertEquals(
                "InternationalSmsQuotaEarlyWarning",
                putRequests.get(1).metricData().get(0).metricName());

        // Verify environment dimension
        for (var request : getRequests) {
            assertEquals("production", request.dimensions().get(0).value());
        }
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
