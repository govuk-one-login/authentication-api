package uk.gov.di.authentication.shared.services;

import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;

import java.util.Optional;

import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoEnhancedClient;

public class BaseDynamoService<T> {

    private final DynamoDbTable<T> dynamoTable;

    public BaseDynamoService(
            Class<T> objectClass, String table, ConfigurationService configurationService) {
        var tableName = configurationService.getEnvironment() + "-" + table;

        dynamoTable =
                createDynamoEnhancedClient(configurationService)
                        .table(tableName, TableSchema.fromBean(objectClass));

        warmUp();
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

    public void delete(String partition) {
        get(partition).ifPresent(dynamoTable::deleteItem);
    }

    private void warmUp() {
        dynamoTable.describeTable();
    }
}
