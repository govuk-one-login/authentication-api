package uk.gov.di.authentication.shared.dynamodb;

import com.amazonaws.client.builder.AwsClientBuilder.EndpointConfiguration;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig.ConsistentReads;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import static com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder.standard;
import static com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig.TableNameOverride.withTableNameReplacement;

public class DynamoClientHelper {

    public static AmazonDynamoDB createDynamoClient(ConfigurationService configurationService) {
        return configurationService
                .getDynamoEndpointUri()
                .map(uri -> new EndpointConfiguration(uri, configurationService.getAwsRegion()))
                .map(standard()::withEndpointConfiguration)
                .orElse(standard().withRegion(configurationService.getAwsRegion()))
                .build();
    }

    public static DynamoDBMapperConfig tableConfig(String tableName) {
        return new DynamoDBMapperConfig.Builder()
                .withTableNameOverride(withTableNameReplacement(tableName))
                .withConsistentReads(ConsistentReads.CONSISTENT)
                .build();
    }
}
