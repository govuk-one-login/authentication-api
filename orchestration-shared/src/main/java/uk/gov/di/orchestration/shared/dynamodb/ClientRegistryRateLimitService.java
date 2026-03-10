package uk.gov.di.orchestration.shared.dynamodb;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class ClientRegistryRateLimitService {
    private ConfigurationService configurationService;
    private DynamoDbClient dynamoDbClient;

    ClientRegistryRateLimitService(
            ConfigurationService configurationService, DynamoDbClient dynamoDbClient) {
        this.configurationService = configurationService;
        this.dynamoDbClient = dynamoDbClient;
    }

    ClientRegistryRateLimitService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dynamoDbClient =
                DynamoDbClient.builder()
                        .credentialsProvider(DefaultCredentialsProvider.builder().build())
                        .build();
    }

    public List<Map<String, AttributeValue>> getAllClients() {
        var scanResult = dynamoDbClient.scan(ScanRequest.builder().build());
        var clients = new ArrayList<>(scanResult.items());
        return clients;
    }
}
