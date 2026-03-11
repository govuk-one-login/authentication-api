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
import uk.gov.di.authentication.frontendapi.lambda.AMCJWKSHandler;
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
class AMCJWKSHandlerIntegrationTest extends HandlerIntegrationTest<Object, String> {
    private static AMCJWKSHandler handler;

    @SystemStub static EnvironmentVariables environmentVariables;

    @RegisterExtension
    protected static final KmsKeyExtension authToAMCSigningKey =
            new KmsKeyExtension("auth-to-amc-signing-key", KeyUsageType.SIGN_VERIFY);

    @RegisterExtension
    private static final KmsKeyExtension authToAccountManagementSigningKey =
            new KmsKeyExtension("auth-to-account-management-signing-key", KeyUsageType.SIGN_VERIFY);

    private static final String AMC_JWKS_BUCKET = "amc-jwks-bucket";
    private static final String AMC_JWKS_FILE_KEY = ".well-known/amc-jwks.json";

    @RegisterExtension
    protected static final S3BucketExtension amcJwksS3 = new S3BucketExtension(AMC_JWKS_BUCKET);

    @BeforeAll
    static void beforeAll() {
        environmentVariables.set("AMC_JWKS_BUCKET_NAME", AMC_JWKS_BUCKET);
        environmentVariables.set(
                "AUTH_TO_ACCOUNT_MANAGEMENT_PRIVATE_SIGNING_KEY",
                authToAccountManagementSigningKey.getKeyAlias());
        environmentVariables.set(
                "AUTH_TO_AMC_PRIVATE_SIGNING_KEY", authToAMCSigningKey.getKeyAlias());

        handler = new AMCJWKSHandler();
    }

    @Test
    void shouldRetrieveKeysAndPutJWKSToS3() throws Exception {
        handler.handleRequest(null, mock(Context.class));

        JWKSet jwks = JWKSet.parse(amcJwksS3.getObject(AMC_JWKS_FILE_KEY));

        String authToAMCKid =
                hashSha256String(
                        "arn:aws:kms:eu-west-2:000000000000:key/" + authToAMCSigningKey.getKeyId());
        String authToAccountManagementKid =
                hashSha256String(
                        "arn:aws:kms:eu-west-2:000000000000:key/"
                                + authToAccountManagementSigningKey.getKeyId());

        assertEquals(2, jwks.getKeys().size());
        assertNotNull(jwks.getKeyByKeyId(authToAMCKid));
        assertNotNull(jwks.getKeyByKeyId(authToAccountManagementKid));

        for (JWK key : jwks.getKeys()) {
            assertEquals(ECKey.class, key.getClass());
            assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
            assertFalse(key.isPrivate());
        }
    }
}
