package uk.gov.di.authentication.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsClient;
import software.amazon.awssdk.services.cloudwatchlogs.model.GetLogEventsRequest;
import software.amazon.awssdk.services.cloudwatchlogs.model.GetLogEventsResponse;

import java.net.URI;

public class CloudWatchExtension implements BeforeAllCallback, AfterAllCallback {
    private CloudWatchLogsClient cloudWatchLogsClient;

    public String getLogGroupName() {
        return logGroupName;
    }

    public String getLogStreamName() {
        return logStreamName;
    }

    private String logGroupName;
    private String logStreamName;

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        logGroupName = context.getTestClass().map(Class::getSimpleName).orElse("unknown");
        logStreamName = context.getTestClass().map(Class::getSimpleName).orElse("unknown");
        cloudWatchLogsClient =
                CloudWatchLogsClient.builder()
                        .endpointOverride(URI.create("http://localhost:45678"))
                        .region(Region.EU_WEST_2)
                        .credentialsProvider(
                                StaticCredentialsProvider.create(
                                        AwsBasicCredentials.create("some-key", "some-secret")))
                        .build();
    }

    @Override
    public void afterAll(ExtensionContext context) {
        if (cloudWatchLogsClient != null) {
            cloudWatchLogsClient.close();
        }
    }

    /**
     * Localstack does not support CloudWatch metrics generation from CloudWatch logs so we have to
     * check the logs for a matching metric log message. This is sufficient as we do not need to
     * test internal AWS functionality just that our lambda initiates the metric creation process
     * correctly.
     *
     * @param metricName name of the metric to be created from the log message
     * @return boolean indicating whether the log message containing the metric was found
     */
    public boolean hasLoggedMetric(String metricName) {
        GetLogEventsRequest request =
                GetLogEventsRequest.builder()
                        .logGroupName(this.logGroupName)
                        .logStreamName(this.logStreamName)
                        .build();

        GetLogEventsResponse response = cloudWatchLogsClient.getLogEvents(request);

        return response.hasEvents()
                && response.events().stream()
                        .anyMatch(event -> event.message().contains(metricName));
    }
}
