package uk.gov.di.authentication.sharedtest.extensions;

import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudwatch.CloudWatchClient;
import software.amazon.awssdk.services.cloudwatch.model.GetMetricDataRequest;
import software.amazon.awssdk.services.cloudwatch.model.Metric;
import software.amazon.awssdk.services.cloudwatch.model.MetricDataQuery;
import software.amazon.awssdk.services.cloudwatch.model.MetricStat;

import java.net.URI;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

public class CloudwatchMetricsExtension extends BaseAwsResourceExtension
        implements BeforeAllCallback {

    protected CloudWatchClient cloudWatch;

    @Override
    public void beforeAll(ExtensionContext context) {
        cloudWatch =
                CloudWatchClient.builder()
                        .region(Region.of(REGION))
                        .endpointOverride(URI.create(LOCALSTACK_ENDPOINT))
                        .build();
    }

    public Double getLastValue(String name) {
        var request =
                GetMetricDataRequest.builder()
                        .metricDataQueries(
                                MetricDataQuery.builder()
                                        .metricStat(
                                                MetricStat.builder()
                                                        .metric(
                                                                Metric.builder()
                                                                        .namespace("Authentication")
                                                                        .metricName(name)
                                                                        .build())
                                                        .period(60)
                                                        .stat("Sum")
                                                        .build())
                                        .id(UUID.randomUUID().toString())
                                        .build())
                        .startTime(Instant.now().minus(1, ChronoUnit.DAYS))
                        .endTime(Instant.now())
                        .build();

        var response = cloudWatch.getMetricData(request);
        if (response.metricDataResults().size() == 0) {
            return 0.0;
        }

        var results = response.metricDataResults().get(0).values();
        if (results.size() == 0) {
            return 0.0;
        }
        return results.get(results.size() - 1);
    }
}
