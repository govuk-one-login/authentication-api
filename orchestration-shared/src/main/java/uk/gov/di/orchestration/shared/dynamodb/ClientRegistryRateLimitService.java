package uk.gov.di.orchestration.shared.dynamodb;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ClientRegistryRateLimitService {
    private ConfigurationService configurationService;
    private DynamoDbClient dynamoDbClient;
    private String tableName;

    ClientRegistryRateLimitService(
            ConfigurationService configurationService, DynamoDbClient dynamoDbClient) {
        this.configurationService = configurationService;
        this.dynamoDbClient = dynamoDbClient;
        this.tableName = configurationService.getEnvironment() + "-" + "client-registry";
    }

    ClientRegistryRateLimitService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dynamoDbClient =
                DynamoDbClient.builder()
                        .credentialsProvider(DefaultCredentialsProvider.builder().build())
                        .build();
        this.tableName = configurationService.getEnvironment() + "-" + "client-registry";
    }

    public List<Map<String, AttributeValue>> getAllClients() {
        var scanResult = dynamoDbClient.scan(ScanRequest.builder().tableName(tableName).build());
        var clients = new ArrayList<>(scanResult.items());

        while (scanResult.hasLastEvaluatedKey() && !scanResult.lastEvaluatedKey().isEmpty()) {
            scanResult =
                    dynamoDbClient.scan(
                            ScanRequest.builder()
                                    .tableName(tableName)
                                    .exclusiveStartKey(scanResult.lastEvaluatedKey())
                                    .build());
            clients.addAll(scanResult.items());
        }
        return clients;
    }

    public void updateClientsWithRateLimit(List<Map<String, AttributeValue>> clients) {
        clients.forEach(
                client -> {
                    var updatedClient = new HashMap<>(client);
                    updatedClient.put("RateLimit", AttributeValue.fromN("2000"));
                    dynamoDbClient.putItem(
                            PutItemRequest.builder()
                                    .tableName(tableName)
                                    .item(updatedClient)
                                    .build());
                });
    }
}
