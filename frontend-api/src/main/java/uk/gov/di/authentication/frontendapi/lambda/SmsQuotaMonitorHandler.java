package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudwatch.CloudWatchClient;
import software.amazon.awssdk.services.cloudwatch.model.Dimension;
import software.amazon.awssdk.services.cloudwatch.model.GetMetricStatisticsRequest;
import software.amazon.awssdk.services.cloudwatch.model.MetricDatum;
import software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest;
import software.amazon.awssdk.services.cloudwatch.model.Statistic;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;

public class SmsQuotaMonitorHandler implements RequestHandler<ScheduledEvent, Void> {

    private final ConfigurationService configurationService;
    private final CloudWatchClient cloudWatchClient;
    private final double domesticSmsQuotaThreshold;
    private final double internationalSmsQuotaThreshold;

    public SmsQuotaMonitorHandler() {
        this.configurationService = ConfigurationService.getInstance();
        this.cloudWatchClient =
                CloudWatchClient.builder()
                        .credentialsProvider(DefaultCredentialsProvider.builder().build())
                        .region(Region.of(configurationService.getAwsRegion()))
                        .build();

        this.domesticSmsQuotaThreshold = configurationService.getDomesticSmsQuotaThreshold();
        this.internationalSmsQuotaThreshold =
                configurationService.getInternationalSmsQuotaThreshold();
    }

    public SmsQuotaMonitorHandler(
            ConfigurationService configurationService, CloudWatchClient cloudWatchClient) {
        this.configurationService = configurationService;
        this.cloudWatchClient = cloudWatchClient;
        this.domesticSmsQuotaThreshold = configurationService.getDomesticSmsQuotaThreshold();
        this.internationalSmsQuotaThreshold =
                configurationService.getInternationalSmsQuotaThreshold();
    }

    @Override
    public Void handleRequest(ScheduledEvent input, Context context) {
        var today = LocalDate.now(ZoneId.of("UTC"));
        var startOfDay = today.atStartOfDay(ZoneId.of("UTC")).toInstant();
        var now = Instant.now();

        var domesticSmsCount = getSmsCountSinceMidnight("DomesticSmsSent", startOfDay, now);
        var internationalSmsCount =
                getSmsCountSinceMidnight("InternationalSmsSent", startOfDay, now);

        emitQuotaWarningMetric(
                "DomesticSmsQuotaEarlyWarning",
                domesticSmsCount >= domesticSmsQuotaThreshold ? 1.0 : 0.0);

        emitQuotaWarningMetric(
                "InternationalSmsQuotaEarlyWarning",
                internationalSmsCount >= internationalSmsQuotaThreshold ? 1.0 : 0.0);

        return null;
    }

    private double getSmsCountSinceMidnight(String metricName, Instant start, Instant end) {
        var durationSeconds = (int) java.time.Duration.between(start, end).getSeconds();
        var periodSeconds =
                ((durationSeconds + 59) / 60) * 60; // Round up to nearest multiple of 60

        var request =
                GetMetricStatisticsRequest.builder()
                        .namespace("Authentication")
                        .metricName(metricName)
                        .dimensions(
                                Dimension.builder()
                                        .name("Environment")
                                        .value(configurationService.getEnvironment())
                                        .build())
                        .startTime(start)
                        .endTime(end)
                        .period(periodSeconds)
                        .statistics(Statistic.SUM)
                        .build();

        var response = cloudWatchClient.getMetricStatistics(request);
        return response.datapoints().stream()
                .findFirst()
                .map(datapoint -> datapoint.sum())
                .orElse(0.0);
    }

    private void emitQuotaWarningMetric(String metricName, double value) {
        var metricDatum =
                MetricDatum.builder()
                        .metricName(metricName)
                        .value(value)
                        .dimensions(
                                Dimension.builder()
                                        .name("Environment")
                                        .value(configurationService.getEnvironment())
                                        .build())
                        .build();

        var request =
                PutMetricDataRequest.builder()
                        .namespace("Authentication")
                        .metricData(metricDatum)
                        .build();

        cloudWatchClient.putMetricData(request);
    }
}
