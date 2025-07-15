package uk.gov.di.authentication.local.initialisers;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.CreateAliasRequest;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import software.amazon.awssdk.services.kms.model.NotFoundException;

import java.net.URI;

import static java.text.MessageFormat.format;
import static software.amazon.awssdk.services.kms.model.KeyUsageType.ENCRYPT_DECRYPT;
import static software.amazon.awssdk.services.kms.model.KeyUsageType.SIGN_VERIFY;

public class KmsInitialiser {
    private final KmsClient kmsClient;

    public KmsInitialiser() {
        this.kmsClient = KmsClient.builder()
            .endpointOverride(URI.create(System.getenv("LOCALSTACK_ENDPOINT")))
            .region(Region.of(System.getenv("AWS_REGION")))
            .credentialsProvider(DefaultCredentialsProvider.create())
            .build();
    }

    public void createKey(String aliasSuffix, KeyUsageType keyUsageType) {
        var keyAlias = format("alias/local-{0}", aliasSuffix);

        if (!keyExists(keyAlias)) {
            if (keyUsageType.equals(ENCRYPT_DECRYPT)) {
                createEncryptionKey(keyAlias);
            } else {
                createTokenSigningKey(keyAlias);
            }
        }
    }

    private void createTokenSigningKey(String keyAlias) {
        var keyRequest =
                CreateKeyRequest.builder()
                        .keyUsage(SIGN_VERIFY)
                        .keySpec(KeySpec.ECC_NIST_P256.toString())
                        .build();
        var keyResponse = kmsClient.createKey(keyRequest);

        CreateAliasRequest aliasRequest =
                CreateAliasRequest.builder()
                        .aliasName(keyAlias)
                        .targetKeyId(keyResponse.keyMetadata().keyId())
                        .build();

        kmsClient.createAlias(aliasRequest);
    }

    private void createEncryptionKey(String keyAlias) {
        CreateKeyRequest keyRequest =
                CreateKeyRequest.builder()
                        .keySpec(KeySpec.RSA_2048)
                        .keyUsage(ENCRYPT_DECRYPT)
                        .build();

        var keyResponse = kmsClient.createKey(keyRequest);

        CreateAliasRequest aliasRequest =
                CreateAliasRequest.builder()
                        .aliasName(keyAlias)
                        .targetKeyId(keyResponse.keyMetadata().keyId())
                        .build();

        kmsClient.createAlias(aliasRequest);
    }

    private boolean keyExists(String keyAlias) {
        try {
            var request = DescribeKeyRequest.builder().keyId(keyAlias).build();
            kmsClient.describeKey(request);
            return true;
        } catch (NotFoundException ignored) {
            return false;
        }
    }
}
