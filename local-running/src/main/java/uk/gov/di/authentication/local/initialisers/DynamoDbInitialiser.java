package uk.gov.di.authentication.local.initialisers;

import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.ResourceNotFoundException;

import java.util.List;

public class DynamoDbInitialiser {
    private final DynamoDbEnhancedClient enhancedClient;

    public DynamoDbInitialiser() {
        var dynamoClient =
                DynamoDbClient.builder()
                        .region(InitialiserConfig.REGION)
                        .endpointOverride(InitialiserConfig.DYNAMO_ENDPOINT)
                        .build();
        this.enhancedClient = DynamoDbEnhancedClient.builder().dynamoDbClient(dynamoClient).build();
    }

    public <T> void addRecords(String tableName, Class<T> modelClass, List<T> records) {
        var table = enhancedClient.table(tableName, TableSchema.fromBean(modelClass));
        try {
            table.describeTable();
        } catch (ResourceNotFoundException e) {
            table.createTable();
        }
        records.forEach(table::putItem);
    }
}
