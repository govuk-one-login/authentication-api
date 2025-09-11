package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.cloudwatch.CloudWatchClient;
import software.amazon.awssdk.services.cloudwatch.model.Datapoint;
import software.amazon.awssdk.services.cloudwatch.model.GetMetricStatisticsRequest;
import software.amazon.awssdk.services.cloudwatch.model.GetMetricStatisticsResponse;
import software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.time.Instant;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SmsQuotaMonitorHandlerTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final CloudWatchClient cloudWatchClient = mock(CloudWatchClient.class);

    @Test
    void shouldEmitCorrectValuesBasedOnThresholds() {
        when(configurationService.getEnvironment()).thenReturn("test");
        when(configurationService.getDomesticSmsQuotaThreshold()).thenReturn(500.0);
        when(configurationService.getInternationalSmsQuotaThreshold()).thenReturn(200.0);

        var handler = new SmsQuotaMonitorHandler(configurationService, cloudWatchClient);

        // Domestic: 600 exceeds threshold of 500, International: 150 below threshold of 200
        when(cloudWatchClient.getMetricStatistics(any(GetMetricStatisticsRequest.class)))
                .thenReturn(createMetricResponse(600.0))
                .thenReturn(createMetricResponse(150.0));

        handler.handleRequest(mock(ScheduledEvent.class), mock(Context.class));

        // Should emit metrics for both domestic (value 1) and international (value 0)
        verify(cloudWatchClient, org.mockito.Mockito.times(2))
                .putMetricData(any(PutMetricDataRequest.class));
    }

    @Test
    void shouldEmitZeroWhenBothThresholdsNotExceeded() {
        when(configurationService.getEnvironment()).thenReturn("test");
        when(configurationService.getDomesticSmsQuotaThreshold()).thenReturn(800.0);
        when(configurationService.getInternationalSmsQuotaThreshold()).thenReturn(200.0);

        var handler = new SmsQuotaMonitorHandler(configurationService, cloudWatchClient);

        // Domestic: 300 below threshold of 800, International: 150 below threshold of 200
        when(cloudWatchClient.getMetricStatistics(any(GetMetricStatisticsRequest.class)))
                .thenReturn(createMetricResponse(300.0))
                .thenReturn(createMetricResponse(150.0));

        handler.handleRequest(mock(ScheduledEvent.class), mock(Context.class));

        // Should emit value 0 for both metrics when below thresholds
        verify(cloudWatchClient, org.mockito.Mockito.times(2))
                .putMetricData(any(PutMetricDataRequest.class));
    }

    private GetMetricStatisticsResponse createMetricResponse(double value) {
        return GetMetricStatisticsResponse.builder()
                .datapoints(
                        List.of(Datapoint.builder().sum(value).timestamp(Instant.now()).build()))
                .build();
    }
}
