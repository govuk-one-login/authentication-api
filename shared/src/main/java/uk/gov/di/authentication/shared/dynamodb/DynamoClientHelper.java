package uk.gov.di.authentication.shared.dynamodb;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.ResourceNotFoundException;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.net.URI;

public class DynamoClientHelper {
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

    public static DynamoDbEnhancedClient createDynamoEnhancedClient(
            ConfigurationService configurationService) {
        var dynamoDbClient = createDynamoClient(configurationService);
        return DynamoDbEnhancedClient.builder().dynamoDbClient(dynamoDbClient).build();
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
}
