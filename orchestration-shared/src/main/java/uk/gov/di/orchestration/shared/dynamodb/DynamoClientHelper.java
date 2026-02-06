package uk.gov.di.orchestration.shared.dynamodb;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClientExtension;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.net.URI;

public class DynamoClientHelper {

    public static DynamoDbClient createDynamoClient(ConfigurationService configurationService) {
        var dynamoDbClientBuilder =
                DynamoDbClient.builder()
                        .credentialsProvider(DefaultCredentialsProvider.builder().build())
                        .region(Region.of(configurationService.getAwsRegion()));
        configurationService
                .getDynamoEndpointURI()
                .ifPresent(
                        endpoint -> dynamoDbClientBuilder.endpointOverride(URI.create(endpoint)));
        return dynamoDbClientBuilder.build();
    }

    public static DynamoDbEnhancedClient createDynamoEnhancedClient(
            ConfigurationService configurationService) {
        var dynamoDbClient = createDynamoClient(configurationService);
        return DynamoDbEnhancedClient.builder().dynamoDbClient(dynamoDbClient).build();
    }

    public static DynamoDbEnhancedClient createDynamoEnhancedClient(
            ConfigurationService configurationService, DynamoDbEnhancedClientExtension extension) {
        var dynamoDbClient = createDynamoClient(configurationService);
        return DynamoDbEnhancedClient.builder()
                .dynamoDbClient(dynamoDbClient)
                .extensions(extension)
                .build();
    }
}
