package uk.gov.di.authentication.local.initialisers;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.ResourceNotFoundException;

import java.net.URI;

public class DynamoDbInitialiser {
    private final DynamoDbEnhancedClient enhancedClient;

    public DynamoDbInitialiser() {
        var dynamoClient = DynamoDbClient.builder()
                .credentialsProvider(DefaultCredentialsProvider.create())
                .region(Region.of(System.getenv("AWS_REGION")))
                .endpointOverride(URI.create(System.getenv("DYNAMO_ENDPOINT")))
                .build();
        this.enhancedClient = DynamoDbEnhancedClient.builder().dynamoDbClient(dynamoClient).build();
    }

    public <T> void createTable(String tableName, Class<T> modelClass) {
        var table = enhancedClient.table(tableName, TableSchema.fromBean(modelClass));
        try {
            table.describeTable();
        } catch (ResourceNotFoundException e) {
            table.createTable();
        }
    }
}
