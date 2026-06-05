package uk.gov.di.authentication.shared.services;

import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.GetItemEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.DescribeTableRequest;
import software.amazon.awssdk.services.dynamodb.model.DescribeTableResponse;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryResponse;
import uk.gov.di.authentication.shared.helpers.TableNameHelper;

import java.util.Optional;

import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoClient;
import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.warmUp;

public class BaseDynamoService<T> {

    protected final DynamoDbTable<T> dynamoTable;
    private final DynamoDbClient client;

    public BaseDynamoService(
            Class<T> objectClass, String table, ConfigurationService configurationService) {
        var tableName = TableNameHelper.getFullTableName(table, configurationService);
        client = createDynamoClient(configurationService);
        var enhancedClient = DynamoDbEnhancedClient.builder().dynamoDbClient(client).build();
        dynamoTable = enhancedClient.table(tableName, TableSchema.fromBean(objectClass));

        warmUp(dynamoTable);
    }

    public BaseDynamoService(DynamoDbTable<T> dynamoTable, DynamoDbClient client) {
        this.dynamoTable = dynamoTable;
        this.client = client;
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

    public Optional<T> get(String partition, String sortKey) {
        return Optional.ofNullable(
                dynamoTable.getItem(
                        Key.builder().partitionValue(partition).sortValue(sortKey).build()));
    }

    public Optional<T> get(GetItemEnhancedRequest getItemEnhancedRequest) {
        return Optional.ofNullable(dynamoTable.getItem(getItemEnhancedRequest));
    }

    public void delete(String partition) {
        get(partition).ifPresent(dynamoTable::deleteItem);
    }

    public void delete(T item) {
        dynamoTable.deleteItem(item);
    }

    public void delete(String partition, String sortKey) {
        get(partition, sortKey).ifPresent(dynamoTable::deleteItem);
    }

    public QueryResponse query(QueryRequest request) {
        return client.query(request);
    }

    public DescribeTableResponse describeTable() {
        return client.describeTable(
                DescribeTableRequest.builder().tableName(dynamoTable.tableName()).build());
    }
}
