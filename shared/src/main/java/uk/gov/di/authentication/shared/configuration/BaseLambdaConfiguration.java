package uk.gov.di.authentication.shared.configuration;

import java.util.Optional;

public interface BaseLambdaConfiguration {

    default String getAwsRegion() {
        return System.getenv("AWS_REGION");
    }

    default String getEnvironment() {
        return System.getenv().getOrDefault("ENVIRONMENT", "test");
    }

    default Optional<String> getLocalstackEndpointUri() {
        return Optional.ofNullable(System.getenv("LOCALSTACK_ENDPOINT"));
    }
}
