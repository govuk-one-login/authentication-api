package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentMatcher;
import software.amazon.awssdk.services.cloudwatch.CloudWatchAsyncClient;
import software.amazon.awssdk.services.cloudwatch.model.MetricDatum;
import software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withExceptionMessage;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class CloudwatchMetricsServiceTest {

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(CloudwatchMetricsService.class);

    @Test
    void shouldPublishMetricValueWithDimensions() {
        var cloudwatch = mock(CloudWatchAsyncClient.class);

        var metrics = new CloudwatchMetricsService(cloudwatch);

        metrics.putValue("metric-name", 10, Map.of("dimension1", "value"));

        verify(cloudwatch).putMetricData(argThat(hasNameAndValue("metric-name", 10d)));
        verify(cloudwatch).putMetricData(argThat(hasDimension("dimension1", "value")));
    }

    @Test
    void shouldIncrementCounter() {
        var cloudwatch = mock(CloudWatchAsyncClient.class);

        var metrics = new CloudwatchMetricsService(cloudwatch);

        metrics.incrementCounter("counter-name", Map.of("dimension2", "value2"));

        verify(cloudwatch).putMetricData(argThat(hasNameAndValue("counter-name", 1.0d)));
        verify(cloudwatch).putMetricData(argThat(hasDimension("dimension2", "value2")));
    }

    @Test
    void shouldLogErrorAndContinueIfProblemPublishingMetric() {
        var cloudwatch = mock(CloudWatchAsyncClient.class);

        var metrics = new CloudwatchMetricsService(cloudwatch);

        when(cloudwatch.putMetricData(any(PutMetricDataRequest.class)))
                .thenThrow(new RuntimeException("Cloudwatch problem"));

        metrics.incrementCounter("counter-name", Map.of("dimension2", "value2"));

        assertThat(logging.events(), hasItem(withMessageContaining("Could not publish metrics")));
        assertThat(logging.events(), hasItem(withExceptionMessage("Cloudwatch problem")));
    }

    private ArgumentMatcher<PutMetricDataRequest> hasNameAndValue(String name, Double value) {
        return (request) ->
                request.metricData().stream()
                        .filter(data -> data.metricName().equals(name))
                        .anyMatch(data -> data.value().equals(value));
    }

    private ArgumentMatcher<PutMetricDataRequest> hasDimension(String name, String value) {
        return (request) ->
                request.metricData().stream()
                        .map(MetricDatum::dimensions)
                        .flatMap(List::stream)
                        .filter(dimension -> dimension.name().equals(name))
                        .anyMatch(dimension -> dimension.value().equals(value));
    }
}
