package uk.gov.di.authentication.sharedtest.doubles;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsClient;
import software.amazon.awssdk.services.cloudwatchlogs.model.CreateLogGroupRequest;
import software.amazon.awssdk.services.cloudwatchlogs.model.CreateLogStreamRequest;
import software.amazon.awssdk.services.cloudwatchlogs.model.InputLogEvent;
import software.amazon.awssdk.services.cloudwatchlogs.model.PutLogEventsRequest;
import software.amazon.cloudwatchlogs.emf.logger.MetricsLogger;
import software.amazon.cloudwatchlogs.emf.model.Unit;

import java.net.URI;
import java.time.Instant;
import java.util.Collections;

public class MetricsLoggerTestDouble extends MetricsLogger {
    private static final Logger log = LogManager.getLogger(MetricsLoggerTestDouble.class);
    private final CloudWatchLogsClient cloudWatchLogsClient;
    private final String logGroupName;
    private final String logStreamName;

    public MetricsLoggerTestDouble(String logGroupName, String logStreamName) {
        this.logGroupName = logGroupName;
        this.logStreamName = logStreamName;
        this.cloudWatchLogsClient =
                CloudWatchLogsClient.builder()
                        .endpointOverride(URI.create("http://localhost:45678"))
                        .region(Region.EU_WEST_2)
                        .credentialsProvider(
                                StaticCredentialsProvider.create(
                                        AwsBasicCredentials.create("dummy", "dummy")))
                        .build();
        cloudWatchLogsClient.createLogGroup(
                CreateLogGroupRequest.builder().logGroupName(logGroupName).build());
        cloudWatchLogsClient.createLogStream(
                CreateLogStreamRequest.builder()
                        .logGroupName(logGroupName)
                        .logStreamName(logStreamName)
                        .build());
    }

    @Override
    public MetricsLogger setNamespace(String namespace) {
        return null;
    }

    @Override
    public MetricsLogger putMetric(String metricName, double value, Unit unit) {
        String message =
                String.format(
                        "{\"metricName\":\"%s\", \"value\": %f, \"timestamp\": %d}",
                        metricName, value, Instant.now().toEpochMilli());

        PutLogEventsRequest request =
                PutLogEventsRequest.builder()
                        .logGroupName(logGroupName)
                        .logStreamName(logStreamName)
                        .logEvents(
                                Collections.singletonList(
                                        InputLogEvent.builder()
                                                .message(message)
                                                .timestamp(Instant.now().toEpochMilli())
                                                .build()))
                        .build();

        cloudWatchLogsClient.putLogEvents(request);
        return null;
    }

    @Override
    public void flush() {
        log.info("NO-OP: flush");
    }
}
