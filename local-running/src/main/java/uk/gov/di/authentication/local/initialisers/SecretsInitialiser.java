package uk.gov.di.authentication.local.initialisers;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.CreateSecretRequest;

public class SecretsInitialiser {
    private final SecretsManagerClient secretsManagerClient;

    public SecretsInitialiser() {
        this.secretsManagerClient =
                SecretsManagerClient.builder()
                        .endpointOverride(InitialiserConfig.LOCALSTACK_ENDPOINT)
                        .region(InitialiserConfig.REGION)
                        .credentialsProvider(DefaultCredentialsProvider.builder().build())
                        .build();
    }

    public void setSecret(String secretId, String value) {
        var secretRequest =
                CreateSecretRequest.builder()
                        .name(secretId)
                        .secretString(value)
                        .forceOverwriteReplicaSecret(true)
                        .build();
        secretsManagerClient.createSecret(secretRequest);
    }
}
