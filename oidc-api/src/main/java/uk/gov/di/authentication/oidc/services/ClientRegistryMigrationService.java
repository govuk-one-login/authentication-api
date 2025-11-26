package uk.gov.di.authentication.oidc.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class ClientRegistryMigrationService {
    public final String tableName;
    private final DynamoDbClient dynamoDbClient;
    private static final String CLIENT_REGISTRY_TABLE = "client-registry";
    private static final Logger LOG = LogManager.getLogger(ClientRegistryMigrationService.class);

    public ClientRegistryMigrationService(
            ConfigurationService configurationService, boolean useTableInOrchAccount) {

        if (configurationService.getDynamoArnPrefix().isPresent() && !useTableInOrchAccount) {
            tableName = configurationService.getDynamoArnPrefix().get() + CLIENT_REGISTRY_TABLE;
        } else {
            tableName = configurationService.getEnvironment() + "-" + CLIENT_REGISTRY_TABLE;
        }

        this.dynamoDbClient =
                DynamoDbClient.builder()
                        .region(Region.of(configurationService.getAwsRegion()))
                        .credentialsProvider(DefaultCredentialsProvider.builder().build())
                        .build();
    }

    public ClientRegistryMigrationService(
            ConfigurationService configurationService,
            boolean useTableInOrchAccount,
            DynamoDbClient dynamoDbClient) {
        if (configurationService.getDynamoArnPrefix().isPresent() && !useTableInOrchAccount) {
            tableName = configurationService.getDynamoArnPrefix().get() + CLIENT_REGISTRY_TABLE;
        } else {
            tableName = configurationService.getEnvironment() + "-" + CLIENT_REGISTRY_TABLE;
        }
        this.dynamoDbClient = dynamoDbClient;
    }

    public void putClientToDynamo(Map<String, AttributeValue> client) {
        try {
            dynamoDbClient.putItem(
                    PutItemRequest.builder().tableName(tableName).item(client).build());
        } catch (Exception e) {
            LOG.error("Failed to put client to dynamo", e);
            throw e;
        }
    }

    public List<Map<String, AttributeValue>> getAllClients() {
        try {
            var scanResult =
                    dynamoDbClient.scan(ScanRequest.builder().tableName(tableName).build());
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
        } catch (Exception e) {
            LOG.error("Failed to get items for migration of client registry", e);
            throw e;
        }
    }
}
