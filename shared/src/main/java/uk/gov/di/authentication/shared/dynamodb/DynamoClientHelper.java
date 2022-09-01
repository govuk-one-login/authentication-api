package uk.gov.di.authentication.shared.dynamodb;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.net.URI;

import static com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder.standard;
import static com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig.TableNameOverride.withTableNameReplacement;

public class DynamoClientHelper {

    public static AmazonDynamoDB createDynamoClient(ConfigurationService configurationService) {
        return configurationService
                .getDynamoEndpointUri()
                .map(
                        uri ->
                                new AwsClientBuilder.EndpointConfiguration(
                                        uri, configurationService.getAwsRegion()))
                .map(standard()::withEndpointConfiguration)
                .orElse(standard().withRegion(configurationService.getAwsRegion()))
                .build();
    }

    public static DynamoDBMapperConfig tableConfig(String tableName) {
        return new DynamoDBMapperConfig.Builder()
                .withTableNameOverride(withTableNameReplacement(tableName))
                .withConsistentReads(DynamoDBMapperConfig.ConsistentReads.CONSISTENT)
                .build();
    }

    public static DynamoDbEnhancedClient createDynamoEnhancedClient(
            ConfigurationService configurationService) {
        var dynamoDbClientBuilder =
                DynamoDbClient.builder()
                        .credentialsProvider(DefaultCredentialsProvider.create())
                        .region(Region.of(configurationService.getAwsRegion()));
        configurationService
                .getDynamoEndpointUri()
                .ifPresent(
                        endpoint -> dynamoDbClientBuilder.endpointOverride(URI.create(endpoint)));
        var dynamoDbClient = dynamoDbClientBuilder.build();
        return DynamoDbEnhancedClient.builder().dynamoDbClient(dynamoDbClient).build();
    }
}
