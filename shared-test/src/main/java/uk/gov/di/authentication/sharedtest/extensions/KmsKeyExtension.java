package uk.gov.di.authentication.sharedtest.extensions;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.CreateAliasRequest;
import com.amazonaws.services.kms.model.CreateKeyRequest;
import com.amazonaws.services.kms.model.CustomerMasterKeySpec;
import com.amazonaws.services.kms.model.DescribeKeyRequest;
import com.amazonaws.services.kms.model.NotFoundException;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import static com.amazonaws.services.kms.model.KeyUsageType.SIGN_VERIFY;
import static java.text.MessageFormat.format;

public class KmsKeyExtension extends BaseAwsResourceExtension implements BeforeAllCallback {

    protected AWSKMS kms;
    protected final String keyAliasSuffix;

    private String keyAlias;

    public KmsKeyExtension(String keyAliasSuffix) {
        this.keyAliasSuffix = keyAliasSuffix;
    }

    @Override
    public void beforeAll(ExtensionContext context) {
        kms =
                AWSKMSClientBuilder.standard()
                        .withEndpointConfiguration(
                                new AwsClientBuilder.EndpointConfiguration(
                                        LOCALSTACK_ENDPOINT, REGION))
                        .build();

        keyAlias =
                format(
                        "alias/{0}-{1}",
                        context.getTestClass().map(Class::getSimpleName).orElse("unknown"),
                        keyAliasSuffix);

        if (!keyExists(keyAlias)) {
            createTokenSigningKey(keyAlias);
        }
    }

    protected void createTokenSigningKey(String keyAlias) {
        CreateKeyRequest keyRequest =
                new CreateKeyRequest()
                        .withCustomerMasterKeySpec(CustomerMasterKeySpec.ECC_NIST_P256)
                        .withKeyUsage(SIGN_VERIFY);

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

    public String getKeyAlias() {
        return keyAlias;
    }
}
