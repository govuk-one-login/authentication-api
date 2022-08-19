package uk.gov.di.authentication.sharedtest.extensions;

import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.ParameterType;
import software.amazon.awssdk.services.ssm.model.PutParameterRequest;

import java.net.URI;
import java.util.Map;

public class ParameterStoreExtension extends BaseAwsResourceExtension implements BeforeAllCallback {
    private final SsmClient ssmClient;

    public ParameterStoreExtension(Map<String, String> parameters) {
        this.ssmClient =
                SsmClient.builder()
                        .endpointOverride(URI.create(LOCALSTACK_ENDPOINT))
                        .region(Region.of(REGION))
                        .credentialsProvider(
                                StaticCredentialsProvider.create(
                                        AwsBasicCredentials.create(
                                                "FAKEACCESSKEY", "FAKESECRETKEY")))
                        .build();

        parameters.forEach(this::createOrOverwriteParameter);
    }

    @Override
    public void beforeAll(ExtensionContext context) {}

    private void createOrOverwriteParameter(String key, String value) {
        var parameterRequest =
                PutParameterRequest.builder()
                        .name(key)
                        .type(ParameterType.SECURE_STRING)
                        .overwrite(true)
                        .value(value)
                        .build();
        ssmClient.putParameter(parameterRequest);
    }

    public SsmClient getClient() {
        return ssmClient;
    }
}
