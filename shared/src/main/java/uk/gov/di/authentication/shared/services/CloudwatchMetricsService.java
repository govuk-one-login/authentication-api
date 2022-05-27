package uk.gov.di.authentication.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudwatch.CloudWatchAsyncClient;
import software.amazon.awssdk.services.cloudwatch.model.Dimension;
import software.amazon.awssdk.services.cloudwatch.model.MetricDatum;
import software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest;
import software.amazon.cloudwatchlogs.emf.logger.MetricsLogger;
import software.amazon.cloudwatchlogs.emf.model.DimensionSet;
import software.amazon.cloudwatchlogs.emf.model.Unit;

import java.net.URI;
import java.util.Map;

import static java.util.stream.Collectors.toList;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class CloudwatchMetricsService {

    private static final Logger LOG = LogManager.getLogger(CloudwatchMetricsService.class);
    private static final MetricsLogger metrics = new MetricsLogger();

    private final CloudWatchAsyncClient cloudwatch;

    public CloudwatchMetricsService(ConfigurationService configurationService) {
        var clientBuilder =
                CloudWatchAsyncClient.builder()
                        .region(Region.of(configurationService.getAwsRegion()));

        configurationService
                .getLocalstackEndpointUri()
                .map(URI::create)
                .ifPresent(clientBuilder::endpointOverride);

        this.cloudwatch = clientBuilder.build();
    }

    public CloudwatchMetricsService(CloudWatchAsyncClient cloudwatch) {
        this.cloudwatch = cloudwatch;
    }

    public static void putEmbeddedValue(String name, double value, Map<String, String> dimensions) {
        segmentedFunctionCall(
                "Metrics::EMF",
                () -> {
                    var dimensionsSet = new DimensionSet();

                    dimensions.forEach(dimensionsSet::addDimension);

                    metrics.setNamespace("Authentication");
                    metrics.putDimensions(dimensionsSet);
                    metrics.putMetric(name, value, Unit.NONE);
                    metrics.flush();
                });
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

        try {
            cloudwatch.putMetricData(request);
        } catch (Exception e) {
            LOG.error("Could not publish metrics", e);
        }
    }

    private Dimension toDimension(Map.Entry<String, String> entry) {
        return Dimension.builder().name(entry.getKey()).value(entry.getValue()).build();
    }

    public void incrementCounter(String name, Map<String, String> dimensions) {
        putValue(name, 1, dimensions);
    }
}
