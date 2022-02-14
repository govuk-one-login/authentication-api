package uk.gov.di.authentication.shared.services;

import software.amazon.awssdk.services.cloudwatch.CloudWatchClient;
import software.amazon.awssdk.services.cloudwatch.model.Dimension;
import software.amazon.awssdk.services.cloudwatch.model.MetricDatum;
import software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest;

import java.util.Map;

import static java.util.stream.Collectors.toList;

public class CloudwatchMetricsService {

    private final CloudWatchClient cloudwatch;

    public CloudwatchMetricsService(CloudWatchClient cloudwatch) {
        this.cloudwatch = cloudwatch;
    }

    public void putValue(String metricName, Number metricValue, Map<String, String> dimensions) {
        var dimensionList = dimensions.entrySet().stream().map(this::toDimension).collect(toList());

        var dataPoint =
                MetricDatum.builder()
                        .metricName(metricName)
                        .value(metricValue.doubleValue())
                        .dimensions(dimensionList)
                        .build();

        var request =
                PutMetricDataRequest.builder()
                        .metricData(dataPoint)
                        .namespace("Authentication")
                        .build();

        cloudwatch.putMetricData(request);
    }

    private Dimension toDimension(Map.Entry<String, String> entry) {
        return Dimension.builder().name(entry.getKey()).value(entry.getValue()).build();
    }

    public void incrementCounter(String name, Map<String, String> dimensions) {
        putValue(name, 1, dimensions);
    }
}
