package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Map;

import static java.text.MessageFormat.format;
import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoClient;

public class AccountMetricPublishHandler implements RequestHandler<ScheduledEvent, Long> {

    private final ConfigurationService configurationService;
    private final AmazonDynamoDB client;
    private final CloudwatchMetricsService cloudwatchMetricsService;

    public AccountMetricPublishHandler(
            ConfigurationService configurationService,
            AmazonDynamoDB client,
            CloudwatchMetricsService cloudwatchMetricsService) {
        this.configurationService = configurationService;
        this.client = client;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
    }

    public AccountMetricPublishHandler() {
        this.configurationService = ConfigurationService.getInstance();
        client = createDynamoClient(configurationService);
        cloudwatchMetricsService = new CloudwatchMetricsService();
    }

    @Override
    public Long handleRequest(ScheduledEvent input, Context context) {
        var result =
                client.describeTable(
                        format("{0}-user-profile", configurationService.getEnvironment()));
        var numberOfAccounts = result.getTable().getItemCount();
        var numberOfVerifiedAccounts =
                result.getTable().getGlobalSecondaryIndexes().stream()
                        .filter(i -> i.getIndexName().equals("VerifiedAccountIndex"))
                        .findFirst()
                        .orElseThrow()
                        .getItemCount();

        cloudwatchMetricsService.putEmbeddedValue("NumberOfAccounts", numberOfAccounts, Map.of());
        cloudwatchMetricsService.putEmbeddedValue(
                "NumberOfVerifiedAccounts", numberOfVerifiedAccounts, Map.of());

        return numberOfVerifiedAccounts;
    }
}
