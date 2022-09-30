package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.DescribeTableRequest;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Map;

import static java.text.MessageFormat.format;
import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoClient;

public class AccountMetricPublishHandler implements RequestHandler<ScheduledEvent, Long> {

    private final ConfigurationService configurationService;
    private final DynamoDbClient client;
    private final CloudwatchMetricsService cloudwatchMetricsService;

    public AccountMetricPublishHandler(
            ConfigurationService configurationService,
            DynamoDbClient client,
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
                        DescribeTableRequest.builder()
                                .tableName(
                                        format(
                                                "{0}-user-profile",
                                                configurationService.getEnvironment()))
                                .build());
        var numberOfAccounts = result.table().itemCount();
        var numberOfVerifiedAccounts =
                result.table().globalSecondaryIndexes().stream()
                        .filter(i -> i.indexName().equals("VerifiedAccountIndex"))
                        .findFirst()
                        .orElseThrow()
                        .itemCount();

        cloudwatchMetricsService.putEmbeddedValue("NumberOfAccounts", numberOfAccounts, Map.of());
        cloudwatchMetricsService.putEmbeddedValue(
                "NumberOfVerifiedAccounts", numberOfVerifiedAccounts, Map.of());

        return numberOfVerifiedAccounts;
    }
}
