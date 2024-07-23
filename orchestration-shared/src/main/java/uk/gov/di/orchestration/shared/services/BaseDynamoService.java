package uk.gov.di.orchestration.shared.services;

import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.DescribeTableRequest;
import software.amazon.awssdk.services.dynamodb.model.DescribeTableResponse;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryResponse;

import java.util.Optional;

import static uk.gov.di.orchestration.shared.dynamodb.DynamoClientHelper.createDynamoClient;

public class BaseDynamoService<T> {

    private final DynamoDbTable<T> dynamoTable;
    private final DynamoDbClient client;

    public BaseDynamoService(
            Class<T> objectClass, String table, ConfigurationService configurationService) {
        this(objectClass, table, configurationService, false);
    }

    public BaseDynamoService(
            Class<T> objectClass,
            String table,
            ConfigurationService configurationService,
            boolean isTableInOrchAccount) {

        var tableName = table;
        if (configurationService.getDynamoArnPrefix().isPresent() && !isTableInOrchAccount) {
            tableName = configurationService.getDynamoArnPrefix().get() + tableName;
        } else {
            tableName = configurationService.getEnvironment() + "-" + tableName;
        }

        client = createDynamoClient(configurationService);
        var enhancedClient = DynamoDbEnhancedClient.builder().dynamoDbClient(client).build();
        dynamoTable = enhancedClient.table(tableName, TableSchema.fromBean(objectClass));

        if (!isTableInOrchAccount) {
            warmUp();
        }
    }

    public void update(T item) {
        dynamoTable.updateItem(item);
    }

    public void put(T item) {
        dynamoTable.putItem(item);
    }

    public Optional<T> get(String partition) {
        return Optional.ofNullable(
                dynamoTable.getItem(Key.builder().partitionValue(partition).build()));
    }

    public Optional<T> get(String partition, String sort) {
        return Optional.ofNullable(
                dynamoTable.getItem(
                        Key.builder().partitionValue(partition).sortValue(sort).build()));
    }

    public void delete(String partition) {
        get(partition).ifPresent(dynamoTable::deleteItem);
    }

    private void warmUp() {
        dynamoTable.describeTable();
    }

    public QueryResponse query(QueryRequest request) {
        return client.query(request);
    }

    public DescribeTableResponse describeTable() {
        return client.describeTable(
                DescribeTableRequest.builder().tableName(dynamoTable.tableName()).build());
    }
}
