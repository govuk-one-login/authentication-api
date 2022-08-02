package uk.gov.di.authentication.sharedtest.extensions;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagement;
import com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagementClient;
import com.amazonaws.services.simplesystemsmanagement.model.PutParameterRequest;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.Map;

import static com.amazonaws.services.simplesystemsmanagement.model.ParameterType.SecureString;

public class ParameterStoreExtension extends BaseAwsResourceExtension implements BeforeAllCallback {
    private final AWSSimpleSystemsManagement ssmClient;

    public ParameterStoreExtension(Map<String, String> parameters) {
        this.ssmClient =
                AWSSimpleSystemsManagementClient.builder()
                        .withEndpointConfiguration(
                                new AwsClientBuilder.EndpointConfiguration(
                                        LOCALSTACK_ENDPOINT, REGION))
                        .build();

        parameters.forEach(this::createOrOverwriteParameter);
    }

    @Override
    public void beforeAll(ExtensionContext context) {}

    private void createOrOverwriteParameter(String key, String value) {
        PutParameterRequest parameterRequest =
                new PutParameterRequest()
                        .withName(key)
                        .withType(SecureString)
                        .withOverwrite(true)
                        .withValue(value);
        ssmClient.putParameter(parameterRequest);
    }

    public AWSSimpleSystemsManagement getClient() {
        return ssmClient;
    }
}
