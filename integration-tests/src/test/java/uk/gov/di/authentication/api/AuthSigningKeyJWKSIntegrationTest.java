package uk.gov.di.authentication.api;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import uk.gov.di.authentication.frontendapi.lambda.MfaResetJarJwkHandler;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.JwksExtension;
import uk.gov.di.authentication.sharedtest.extensions.KmsKeyExtension;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.net.MalformedURLException;
import java.net.URI;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.shared.helpers.HashHelper.hashSha256String;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

@ExtendWith(SystemStubsExtension.class)
class AuthSigningKeyJWKSIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final Logger LOG = LogManager.getLogger(AuthSigningKeyJWKSIntegrationTest.class);

    @SystemStub private static final EnvironmentVariables environment = new EnvironmentVariables();

    @RegisterExtension public static final JwksExtension jwksExtension = new JwksExtension();

    @RegisterExtension
    private static final KmsKeyExtension mfaResetJarSigningKey =
            new KmsKeyExtension("mfa-reset-jar-signing-key", KeyUsageType.SIGN_VERIFY);

    @RegisterExtension
    private static final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(MfaResetJarJwkHandler.class);

    private static String expectedHashKeyArn;

    @BeforeAll
    static void setupEnvironment() throws MalformedURLException {
        environment.set("ACCESS_TOKEN_JWKS_URL", jwksExtension.getJwksUrl());

        try (KmsClient kmsClient = getKmsClient()) {
            GetPublicKeyRequest getPublicKeyRequest =
                    GetPublicKeyRequest.builder().keyId(mfaResetJarSigningKey.getKeyId()).build();

            GetPublicKeyResponse getPublicKeyResponse = kmsClient.getPublicKey(getPublicKeyRequest);

            expectedHashKeyArn = hashSha256String(getPublicKeyResponse.keyId());
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        }
    }

    @BeforeEach
    void setup() {
        environment.set(
                "IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_ALIAS", mfaResetJarSigningKey.getKeyId());
    }

    private static KmsClient getKmsClient() {
        return KmsClient.builder()
                .endpointOverride(URI.create("http://localhost:45678"))
                .credentialsProvider(
                        StaticCredentialsProvider.create(
                                AwsBasicCredentials.create("dummy", "dummy")))
                .region(Region.EU_WEST_2)
                .build();
    }

    @Test
    void shouldReturnJWKSetContainingTheReverificationSigningKey() {
        handler = new MfaResetJarJwkHandler(TEST_CONFIGURATION_SERVICE);

        var response = makeRequest(Optional.empty(), Map.of(), Map.of());

        assertThat(response, hasStatus(200));

        JsonObject jwk = JsonParser.parseString(response.getBody()).getAsJsonObject();
        JsonArray keys = jwk.get("keys").getAsJsonArray();
        assertEquals(1, keys.size(), "JWKS endpoint must return a single key.");

        checkPublicSigningKeyResponseMeetsADR0030(keys.get(0).getAsJsonObject());
    }

    @Test
    void shouldNotAllowExceptionsToEscape() {
        environment.set("IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_ALIAS", "wrong-key-alias");

        handler = new MfaResetJarJwkHandler(TEST_CONFIGURATION_SERVICE);

        var response = makeRequest(Optional.empty(), Map.of(), Map.of());

        assertThat(response, hasStatus(500));
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "Failed to serve Auth reverification request JAR signature verification key.")));
    }

    private static void checkPublicSigningKeyResponseMeetsADR0030(JsonObject key) {
        assertEquals(expectedHashKeyArn, key.get("kid").getAsString());
        assertEquals(KeyType.EC.getValue(), key.get("kty").getAsString());
        assertEquals(KeyUse.SIGNATURE.getValue(), key.get("use").getAsString());
        assertEquals(Curve.P_256.getName(), key.get("crv").getAsString());
        assertEquals(JWSAlgorithm.ES256.toString(), key.get("alg").getAsString());
    }
}
