package uk.gov.di.orchestration.sharedtest.basetest;

import uk.gov.di.orchestration.shared.services.ConfigurationService;

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
    public Optional<String> getDynamoEndpointURI() {
        return Optional.of(dynamoDbUri);
    }
}
