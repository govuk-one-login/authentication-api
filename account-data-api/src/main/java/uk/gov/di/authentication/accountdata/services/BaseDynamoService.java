package uk.gov.di.authentication.accountdata.services;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Expression;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.GetItemEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryEnhancedRequest;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.ResourceNotFoundException;

import java.net.URI;
import java.util.List;
import java.util.Optional;

public class BaseDynamoService<T> {

    protected final DynamoDbTable<T> dynamoTable;

    public BaseDynamoService(
            Class<T> objectClass, String table, ConfigurationService configurationService) {
        var tableName = getFullTableName(table, configurationService);
        DynamoDbClient client = createDynamoClient(configurationService);
        var enhancedClient = DynamoDbEnhancedClient.builder().dynamoDbClient(client).build();
        dynamoTable = enhancedClient.table(tableName, TableSchema.fromBean(objectClass));

        warmUp(dynamoTable);
    }

    public static DynamoDbClient createDynamoClient(ConfigurationService configurationService) {
        var dynamoDbClientBuilder =
                DynamoDbClient.builder()
                        .credentialsProvider(DefaultCredentialsProvider.builder().build())
                        .region(Region.of(configurationService.getAwsRegion()));
        configurationService
                .getDynamoEndpointUri()
                .ifPresent(
                        endpoint -> dynamoDbClientBuilder.endpointOverride(URI.create(endpoint)));
        return dynamoDbClientBuilder.build();
    }

    public static void warmUp(DynamoDbTable<?> table) {
        try {
            table.describeTable();
        } catch (ResourceNotFoundException e) {
            if ("local".equals(System.getenv("ENVIRONMENT"))) {
                table.createTable();
            } else {
                throw e;
            }
        }
    }

    private static String getFullTableName(
            String tableName, ConfigurationService configurationService) {
        Optional<String> authDynamoArnPrefix = configurationService.getDynamoArnPrefix();
        if (authDynamoArnPrefix.isPresent()) {
            return authDynamoArnPrefix.get()
                    + configurationService.getEnvironment()
                    + "-"
                    + tableName;
        }
        return configurationService.getEnvironment() + "-" + tableName;
    }

    public void update(T item) {
        dynamoTable.updateItem(item);
    }

    public boolean putIfUnique(T item, String key) {
        try {
            dynamoTable.putItem(
                    builder ->
                            builder.item(item)
                                    .conditionExpression(
                                            Expression.builder()
                                                    .expression("attribute_not_exists(#key)")
                                                    .putExpressionName("#key", key)
                                                    .build()));
            return true;
        } catch (ConditionalCheckFailedException e) {
            return false;
        }
    }

    public Optional<T> get(String partition) {

        return Optional.ofNullable(
                dynamoTable.getItem(Key.builder().partitionValue(partition).build()));
    }

    public Optional<T> get(String partition, String sortKey) {
        return Optional.ofNullable(
                dynamoTable.getItem(
                        Key.builder().partitionValue(partition).sortValue(sortKey).build()));
    }

    public Optional<T> get(GetItemEnhancedRequest getItemEnhancedRequest) {
        return Optional.ofNullable(dynamoTable.getItem(getItemEnhancedRequest));
    }

    public List<T> getAllByPrefix(String partition, String sortKeyPrefix) {
        QueryConditional queryConditional =
                QueryConditional.sortBeginsWith(
                        Key.builder().partitionValue(partition).sortValue(sortKeyPrefix).build());
        return dynamoTable
                .query(
                        QueryEnhancedRequest.builder()
                                .consistentRead(true)
                                .queryConditional(queryConditional)
                                .build())
                .items()
                .stream()
                .toList();
    }

    public void delete(T item) {
        dynamoTable.deleteItem(item);
    }
}
