package uk.gov.di.authentication.shared.configuration;

import java.util.Optional;

public interface DynamoConfiguration extends BaseLambdaConfiguration {

    Optional<String> getDynamoArnPrefix();

    Optional<String> getDynamoEndpointUri();
}
