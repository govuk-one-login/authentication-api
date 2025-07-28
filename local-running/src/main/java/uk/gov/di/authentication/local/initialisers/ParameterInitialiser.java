package uk.gov.di.authentication.local.initialisers;

import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.ParameterType;
import software.amazon.awssdk.services.ssm.model.PutParameterRequest;

public class ParameterInitialiser {
    private final SsmClient ssmClient;

    public ParameterInitialiser() {
        this.ssmClient =
                SsmClient.builder()
                        .endpointOverride(InitialiserConfig.LOCALSTACK_ENDPOINT)
                        .region(InitialiserConfig.REGION)
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
