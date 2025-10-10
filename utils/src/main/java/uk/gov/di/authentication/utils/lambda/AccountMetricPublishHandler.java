package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.ScanEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.DescribeTableRequest;
import software.amazon.awssdk.enhanced.dynamodb.Expression;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Map;

import static java.text.MessageFormat.format;
import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoClient;
import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoEnhancedClient;

public class AccountMetricPublishHandler implements RequestHandler<ScheduledEvent, Long> {

    private final ConfigurationService configurationService;
    private final DynamoDbClient client;
    private final DynamoDbEnhancedClient enhancedClient;
    private final CloudwatchMetricsService cloudwatchMetricsService;

    public AccountMetricPublishHandler(
            ConfigurationService configurationService,
            DynamoDbClient client,
            DynamoDbEnhancedClient enhancedClient,
            CloudwatchMetricsService cloudwatchMetricsService) {
        this.configurationService = configurationService;
        this.client = client;
        this.enhancedClient = enhancedClient;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
    }

    public AccountMetricPublishHandler() {
        this.configurationService = ConfigurationService.getInstance();
        client = createDynamoClient(configurationService);
        enhancedClient = createDynamoEnhancedClient(configurationService);
        cloudwatchMetricsService = new CloudwatchMetricsService();
    }

    @Override
    public Long handleRequest(ScheduledEvent input, Context context) {
        var accountCounts = getAccountCounts();
        var nonUkPhoneNumbers = countNonUkPhoneNumbersForVerifiedAccounts();

        cloudwatchMetricsService.putEmbeddedValue("NumberOfAccounts", accountCounts.totalAccounts(), Map.of());
        cloudwatchMetricsService.putEmbeddedValue(
                "NumberOfVerifiedAccounts", accountCounts.verifiedAccounts(), Map.of());
        cloudwatchMetricsService.putEmbeddedValue(
                "NonUkPhoneNumbersVerifiedAccounts", nonUkPhoneNumbers, Map.of());

        return accountCounts.verifiedAccounts();
    }

    private AccountCounts getAccountCounts() {
        var result = client.describeTable(
                DescribeTableRequest.builder()
                        .tableName(format("{0}-user-profile", configurationService.getEnvironment()))
                        .build());
        
        var totalAccounts = result.table().itemCount();
        var verifiedAccounts = result.table().globalSecondaryIndexes().stream()
                .filter(i -> i.indexName().equals("VerifiedAccountIndex"))
                .findFirst()
                .orElseThrow()
                .itemCount();
        
        return new AccountCounts(totalAccounts, verifiedAccounts);
    }

    private record AccountCounts(long totalAccounts, long verifiedAccounts) {}

    private long countNonUkPhoneNumbersForVerifiedAccounts() {
        var tableName = format("{0}-user-profile", configurationService.getEnvironment());
        var table = enhancedClient.table(tableName, TableSchema.fromBean(UserProfile.class));
        
        var filterExpression = Expression.builder()
                .expression("accountVerified = :verified AND attribute_exists(PhoneNumber) AND NOT begins_with(PhoneNumber, :ukPrefix)")
                .putExpressionValue(":verified", AttributeValue.builder().n("1").build())
                .putExpressionValue(":ukPrefix", AttributeValue.builder().s("+44").build())
                .build();
        
        var scanRequest = ScanEnhancedRequest.builder()
                .filterExpression(filterExpression)
                .build();
        
        return table.scan(scanRequest).items().stream().count();
    }
}
