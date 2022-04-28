package uk.gov.di.authentication.sharedtest.basetest;

import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Optional;

public class DynamoTestConfiguration extends ConfigurationService {

    private final String region;
    private final String environment;
    private final String dynamoDbUri;

    public DynamoTestConfiguration(String region, String environment, String dynamoDbUri) {
        this.region = region;
        this.environment = environment;
        this.dynamoDbUri = dynamoDbUri;
    }

    @Override
    public String getAwsRegion() {
        return region;
    }

    @Override
    public String getEnvironment() {
        return environment;
    }

    @Override
    public Optional<String> getDynamoEndpointUri() {
        return Optional.of(dynamoDbUri);
    }
}
