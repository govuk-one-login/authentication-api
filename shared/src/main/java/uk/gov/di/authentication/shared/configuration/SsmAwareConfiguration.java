package uk.gov.di.authentication.shared.configuration;

import com.amazonaws.client.builder.AwsClientBuilder.EndpointConfiguration;
import com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagement;
import com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagementClient;

import java.util.Optional;

public class SsmAwareConfiguration {
    private static final String REGION = System.getenv("AWS_REGION");

    private static final AWSSimpleSystemsManagement SSM_CLIENT =
            Optional.ofNullable(System.getenv("LOCALSTACK_ENDPOINT"))
                    .map(l -> new EndpointConfiguration(l, REGION))
                    .map(AWSSimpleSystemsManagementClient.builder()::withEndpointConfiguration)
                    .orElse(AWSSimpleSystemsManagementClient.builder().withRegion(REGION))
                    .build();
}
