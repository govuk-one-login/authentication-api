package uk.gov.di.authentication.sharedtest.extensions;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.CreateAliasRequest;
import com.amazonaws.services.kms.model.CreateKeyRequest;
import com.amazonaws.services.kms.model.DescribeKeyRequest;
import com.amazonaws.services.kms.model.NotFoundException;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import static com.amazonaws.services.kms.model.KeySpec.ECC_NIST_P256;

public class KmsKeyExtension implements BeforeAllCallback {

    protected static final String REGION = System.getenv().getOrDefault("AWS_REGION", "eu-west-2");
    protected static final String LOCALSTACK_ENDPOINT =
            System.getenv().getOrDefault("LOCALSTACK_ENDPOINT", "http://localhost:45678");

    protected AWSKMS kms;
    protected final String keyAlias;

    public KmsKeyExtension(String keyAlias) {
        this.keyAlias = keyAlias;
    }

    @Override
    public void beforeAll(ExtensionContext context) {
        kms =
                AWSKMSClientBuilder.standard()
                        .withEndpointConfiguration(
                                new AwsClientBuilder.EndpointConfiguration(
                                        LOCALSTACK_ENDPOINT, REGION))
                        .build();

        if (!keyExists(keyAlias)) {
            createTokenSigningKey(keyAlias);
        }
    }

    protected void createTokenSigningKey(String keyAlias) {
        CreateKeyRequest keyRequest =
                new CreateKeyRequest().withKeySpec(ECC_NIST_P256).withKeyUsage("SIGN_VERIFY");

        var keyResponse = kms.createKey(keyRequest);

        CreateAliasRequest aliasRequest =
                new CreateAliasRequest()
                        .withAliasName(keyAlias)
                        .withTargetKeyId(keyResponse.getKeyMetadata().getKeyId());

        kms.createAlias(aliasRequest);
    }

    protected boolean keyExists(String keyAlias) {
        try {
            var request = new DescribeKeyRequest().withKeyId(keyAlias);
            kms.describeKey(request);
            return true;
        } catch (NotFoundException ignored) {
            return false;
        }
    }
}
