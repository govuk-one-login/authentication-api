package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudwatch.CloudWatchClient;
import software.amazon.awssdk.services.cloudwatch.model.Datapoint;
import software.amazon.awssdk.services.cloudwatch.model.Dimension;
import software.amazon.awssdk.services.cloudwatch.model.GetMetricStatisticsRequest;
import software.amazon.awssdk.services.cloudwatch.model.MetricDatum;
import software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest;
import software.amazon.awssdk.services.cloudwatch.model.Statistic;
import uk.gov.di.authentication.entity.Application;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;

import static uk.gov.di.authentication.entity.Application.AUTHENTICATION;
import static uk.gov.di.authentication.entity.Application.ONE_LOGIN_HOME;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.APPLICATION;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.LOG_GROUP;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.SERVICE_NAME;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.SERVICE_TYPE;

public class SmsQuotaMonitorHandler implements RequestHandler<ScheduledEvent, Void> {

    private static final Logger LOG = LogManager.getLogger(SmsQuotaMonitorHandler.class);
    private static final String LAMBDA_FUNCTION_SERVICE_TYPE = "AWS::Lambda::Function";

    private final ConfigurationService configurationService;
    private final CloudWatchClient cloudWatchClient;
    private final double domesticSmsQuotaThreshold;
    private final double internationalSmsQuotaThreshold;
    private final String smsSentMetricProducer;

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
        this.smsSentMetricProducer = configurationService.getEmailSqsLambdaFunctionName();
    }

    public SmsQuotaMonitorHandler(
            ConfigurationService configurationService, CloudWatchClient cloudWatchClient) {
        this.configurationService = configurationService;
        this.cloudWatchClient = cloudWatchClient;
        this.domesticSmsQuotaThreshold = configurationService.getDomesticSmsQuotaThreshold();
        this.internationalSmsQuotaThreshold =
                configurationService.getInternationalSmsQuotaThreshold();
        this.smsSentMetricProducer = configurationService.getEmailSqsLambdaFunctionName();
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

        LOG.info(
                "domesticSmsCount: {}, domesticSmsQuotaThreshold: {}",
                domesticSmsCount,
                domesticSmsQuotaThreshold);
        LOG.info(
                "internationalSmsCount: {}, internationalSmsQuotaThreshold: {}",
                internationalSmsCount,
                internationalSmsQuotaThreshold);

        return null;
    }

    private double getSmsCountSinceMidnight(String metricName, Instant start, Instant end) {
        var durationSeconds = (int) java.time.Duration.between(start, end).getSeconds();
        var periodSeconds =
                ((durationSeconds + 59) / 60) * 60; // Round up to nearest multiple of 60

        var authCount =
                getSmsCountByApplication(AUTHENTICATION, metricName, start, end, periodSeconds);
        var homeCount =
                getSmsCountByApplication(ONE_LOGIN_HOME, metricName, start, end, periodSeconds);

        return authCount + homeCount;
    }

    private Double getSmsCountByApplication(
            Application application,
            String metricName,
            Instant start,
            Instant end,
            int periodSeconds) {
        var metricRequest = buildMetricRequest(metricName, application, start, end, periodSeconds);

        var response = cloudWatchClient.getMetricStatistics(metricRequest);

        var smsCount = response.datapoints().stream().findFirst().map(Datapoint::sum).orElse(0.0);
        LOG.info("{} count for application '{}': {}", metricName, application.getValue(), smsCount);

        return smsCount;
    }

    private GetMetricStatisticsRequest buildMetricRequest(
            String metricName,
            Application application,
            Instant start,
            Instant end,
            int periodSeconds) {
        // NOTE: All dimensions must be provided here, including those added by the AWS EMF
        // MetricsLogger.
        return GetMetricStatisticsRequest.builder()
                .namespace("Authentication")
                .metricName(metricName)
                .dimensions(
                        Dimension.builder()
                                .name(ENVIRONMENT.getValue())
                                .value(configurationService.getEnvironment())
                                .build(),
                        Dimension.builder()
                                .name(APPLICATION.getValue())
                                .value(application.getValue())
                                .build(),
                        Dimension.builder()
                                .name(LOG_GROUP.getValue())
                                .value(smsSentMetricProducer)
                                .build(),
                        Dimension.builder()
                                .name(SERVICE_NAME.getValue())
                                .value(smsSentMetricProducer)
                                .build(),
                        Dimension.builder()
                                .name(SERVICE_TYPE.getValue())
                                .value(LAMBDA_FUNCTION_SERVICE_TYPE)
                                .build())
                .startTime(start)
                .endTime(end)
                .period(periodSeconds)
                .statistics(Statistic.SUM)
                .build();
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
