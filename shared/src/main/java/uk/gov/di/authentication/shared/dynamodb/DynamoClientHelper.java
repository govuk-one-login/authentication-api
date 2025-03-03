package uk.gov.di.authentication.shared.dynamodb;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.tracing.ConditionalOtelTracingExecutionInterceptor;

import java.net.URI;

public class DynamoClientHelper {

    public static DynamoDbClient createDynamoClient(ConfigurationService configurationService) {
        var dynamoDbClientBuilder =
                DynamoDbClient.builder()
                        .overrideConfiguration(
                                ClientOverrideConfiguration.builder()
                                        .addExecutionInterceptor(
                                                new ConditionalOtelTracingExecutionInterceptor())
                                        .build())
                        .credentialsProvider(DefaultCredentialsProvider.create())
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
}
