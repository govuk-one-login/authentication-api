package uk.gov.di.authentication.api;

import com.amazonaws.services.lambda.runtime.Context;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import uk.gov.di.authentication.frontendapi.lambda.ADJWKSHandler;
import uk.gov.di.authentication.sharedtest.basetest.HandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.KmsKeyExtension;
import uk.gov.di.authentication.sharedtest.extensions.S3BucketExtension;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static uk.gov.di.authentication.shared.helpers.HashHelper.hashSha256String;

@ExtendWith(SystemStubsExtension.class)
class ADJWKSHandlerIntegrationTest extends HandlerIntegrationTest<Object, String> {
    private static ADJWKSHandler handler;

    @SystemStub static EnvironmentVariables environmentVariables;

    @RegisterExtension
    private static final KmsKeyExtension authToAccountDataSigningKey =
            new KmsKeyExtension("auth-to-account-data-signing-key", KeyUsageType.SIGN_VERIFY);

    private static final String AD_JWKS_BUCKET = "ad-jwks-bucket";
    private static final String AD_JWKS_FILE_KEY = ".well-known/ad-jwks.json";

    @RegisterExtension
    protected static final S3BucketExtension adJwksS3 = new S3BucketExtension(AD_JWKS_BUCKET);

    @BeforeAll
    static void beforeAll() {
        environmentVariables.set("AD_JWKS_BUCKET_NAME", AD_JWKS_BUCKET);
        environmentVariables.set(
                "AUTH_TO_ACCOUNT_DATA_SIGNING_KEY", authToAccountDataSigningKey.getKeyAlias());

        handler = new ADJWKSHandler();
    }

    @Test
    void shouldRetrieveKeysAndPutJWKSToS3() throws Exception {
        handler.handleRequest(null, mock(Context.class));

        JWKSet jwks = JWKSet.parse(adJwksS3.getObject(AD_JWKS_FILE_KEY));

        String authToAccountDataKid =
                hashSha256String(
                        "arn:aws:kms:eu-west-2:000000000000:key/"
                                + authToAccountDataSigningKey.getKeyId());

        assertEquals(1, jwks.getKeys().size());
        assertNotNull(jwks.getKeyByKeyId(authToAccountDataKid));

        for (JWK key : jwks.getKeys()) {
            assertEquals(ECKey.class, key.getClass());
            assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
            assertFalse(key.isPrivate());
        }
    }
}
