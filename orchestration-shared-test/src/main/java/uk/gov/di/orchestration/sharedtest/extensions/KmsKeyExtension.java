package uk.gov.di.orchestration.sharedtest.extensions;

import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
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

public class KmsKeyExtension extends BaseAwsResourceExtension implements BeforeAllCallback {

    protected KmsClient kms;
    protected final String keyAliasSuffix;

    private String keyAlias;
    private final KeyUsageType keyUsageType;

    public KmsKeyExtension(String keyAliasSuffix) {
        this(keyAliasSuffix, SIGN_VERIFY);
    }

    public KmsKeyExtension(String keyAliasSuffix, KeyUsageType keyUsageType) {
        this.keyAliasSuffix = keyAliasSuffix;
        this.keyUsageType = keyUsageType;
    }

    @Override
    public void beforeAll(ExtensionContext context) {
        kms =
                KmsClient.builder()
                        .endpointOverride(URI.create(LOCALSTACK_ENDPOINT))
                        .region(Region.of(REGION))
                        .credentialsProvider(DefaultCredentialsProvider.builder().build())
                        .build();

        keyAlias =
                format(
                        "alias/{0}-{1}",
                        context.getTestClass().map(Class::getSimpleName).orElse("unknown"),
                        keyAliasSuffix);

        if (!keyExists(keyAlias)) {
            if (keyUsageType.equals(ENCRYPT_DECRYPT)) {
                createEncryptionKey(keyAlias);
            } else {
                createTokenSigningKey(keyAlias);
            }
        }
    }

    // https://github.com/aws/aws-sdk/issues/125
    @SuppressWarnings("deprecation")
    protected void createTokenSigningKey(String keyAlias) {
        var keyRequest =
                CreateKeyRequest.builder()
                        .keyUsage(SIGN_VERIFY)
                        .customerMasterKeySpec(KeySpec.ECC_NIST_P256.toString())
                        .build();
        var keyResponse = kms.createKey(keyRequest);

        CreateAliasRequest aliasRequest =
                CreateAliasRequest.builder()
                        .aliasName(keyAlias)
                        .targetKeyId(keyResponse.keyMetadata().keyId())
                        .build();

        kms.createAlias(aliasRequest);
    }

    protected void createEncryptionKey(String keyAlias) {
        CreateKeyRequest keyRequest =
                CreateKeyRequest.builder()
                        .keySpec(KeySpec.RSA_2048)
                        .keyUsage(ENCRYPT_DECRYPT)
                        .build();

        var keyResponse = kms.createKey(keyRequest);

        CreateAliasRequest aliasRequest =
                CreateAliasRequest.builder()
                        .aliasName(keyAlias)
                        .targetKeyId(keyResponse.keyMetadata().keyId())
                        .build();

        kms.createAlias(aliasRequest);
    }

    protected boolean keyExists(String keyAlias) {
        try {
            var request = DescribeKeyRequest.builder().keyId(keyAlias).build();
            kms.describeKey(request);
            return true;
        } catch (NotFoundException ignored) {
            return false;
        }
    }

    public String getKeyAlias() {
        return keyAlias;
    }
}
