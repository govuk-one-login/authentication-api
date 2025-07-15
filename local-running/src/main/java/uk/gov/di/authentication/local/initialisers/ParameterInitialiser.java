package uk.gov.di.authentication.local.initialisers;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.ParameterType;
import software.amazon.awssdk.services.ssm.model.PutParameterRequest;

import java.net.URI;

// Combination of code in ParameterStoreExtension and HandlerIntegrationTest
// Perhaps we can commonise?
public class ParameterInitialiser {
    private final SsmClient ssmClient;

    public ParameterInitialiser() {
        this.ssmClient = SsmClient.builder()
                .endpointOverride(URI.create(System.getenv("LOCALSTACK_ENDPOINT")))
                .region(Region.of(System.getenv("AWS_REGION")))
                .credentialsProvider(
                        StaticCredentialsProvider.create(
                                AwsBasicCredentials.create(
                                        "FAKEACCESSKEY", "FAKESECRETKEY")))
                .build();
    }

    public void setParam(String key, String value) {
        var parameterRequest =
                PutParameterRequest.builder()
                        .name(key)
                        .type(ParameterType.SECURE_STRING)
                        .overwrite(true)
                        .value(value)
                        .build();
        ssmClient.putParameter(parameterRequest);
    }
}
