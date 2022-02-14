package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatcher;
import software.amazon.awssdk.services.cloudwatch.CloudWatchClient;
import software.amazon.awssdk.services.cloudwatch.model.MetricDatum;
import software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest;

import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class CloudwatchMetricsServiceTest {

    @Test
    void shouldPublishMetricValueWithDimensions() {
        var cloudwatch = mock(CloudWatchClient.class);

        var metrics =
                new CloudwatchMetricsService(cloudwatch) {
                    @Override
                    protected boolean enabled() {
                        return true;
                    }
                };

        metrics.putValue("metric-name", 10, Map.of("dimension1", "value"));

        verify(cloudwatch).putMetricData(argThat(hasNameAndValue("metric-name", 10d)));
        verify(cloudwatch).putMetricData(argThat(hasDimension("dimension1", "value")));
    }

    @Test
    void shouldIncrementCounter() {
        var cloudwatch = mock(CloudWatchClient.class);

        var metrics =
                new CloudwatchMetricsService(cloudwatch) {
                    @Override
                    protected boolean enabled() {
                        return true;
                    }
                };

        metrics.incrementCounter("counter-name", Map.of("dimension2", "value2"));

        verify(cloudwatch).putMetricData(argThat(hasNameAndValue("counter-name", 1.0d)));
        verify(cloudwatch).putMetricData(argThat(hasDimension("dimension2", "value2")));
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
