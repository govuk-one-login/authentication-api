package uk.gov.di.authentication.sharedtest.extensions;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagement;
import com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagementClient;
import com.amazonaws.services.simplesystemsmanagement.model.PutParameterRequest;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.Map;

import static com.amazonaws.services.simplesystemsmanagement.model.ParameterType.SecureString;

public class ParameterStoreExtension implements BeforeAllCallback {

    protected static final String REGION = System.getenv().getOrDefault("AWS_REGION", "eu-west-2");
    protected static final String LOCALSTACK_ENDPOINT =
            System.getenv().getOrDefault("LOCALSTACK_ENDPOINT", "http://localhost:45678");

    private final Map<String, String> parameters;
    private final AWSSimpleSystemsManagement ssmClient;

    public ParameterStoreExtension(Map<String, String> parameters) {
        this.parameters = parameters;
        this.ssmClient =
                AWSSimpleSystemsManagementClient.builder()
                        .withEndpointConfiguration(
                                new AwsClientBuilder.EndpointConfiguration(
                                        LOCALSTACK_ENDPOINT, REGION))
                        .build();
    }

    @Override
    public void beforeAll(ExtensionContext context) {
        parameters.forEach(this::createOrOverwriteParameter);
    }

    private void createOrOverwriteParameter(String key, String value) {
        PutParameterRequest parameterRequest =
                new PutParameterRequest()
                        .withName(key)
                        .withType(SecureString)
                        .withOverwrite(true)
                        .withValue(value);
        ssmClient.putParameter(parameterRequest);
    }
}
