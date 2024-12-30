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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.CreateAliasRequest;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.CreateKeyResponse;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import uk.gov.di.authentication.frontendapi.lambda.MfaResetJarJwkHandler;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.net.URI;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.shared.helpers.HashHelper.hashSha256String;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

@ExtendWith(SystemStubsExtension.class)
class AuthSigningKeyJWKSIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final Logger LOG = LogManager.getLogger(AuthSigningKeyJWKSIntegrationTest.class);
    public static final String MFA_RESET_JAR_SIGNING_KEY =
            "localstack-mfa-reset-jar-signing-key-ecc-alias";
    public static final String MFA_RESET_JAR_SIGNING_KEY_ALIAS =
            "alias/" + MFA_RESET_JAR_SIGNING_KEY;

    @SystemStub static EnvironmentVariables environment = new EnvironmentVariables();

    private static String expectedKid;

    @BeforeAll
    static void setupEnvironment() {
        try (KmsClient kmsClient = getKmsClient()) {
            CreateKeyRequest createKeyRequest =
                    CreateKeyRequest.builder()
                            .description(MFA_RESET_JAR_SIGNING_KEY)
                            .keyUsage(KeyUsageType.SIGN_VERIFY)
                            .keySpec(KeySpec.ECC_NIST_P256)
                            .build();

            CreateKeyResponse createKeyResponse = kmsClient.createKey(createKeyRequest);

            LOG.info("KMS Key ID: {}", createKeyResponse.keyMetadata().keyId());
            LOG.info("KMS Key arn: {}", createKeyResponse.keyMetadata().arn());

            environment.set(
                    "MFA_RESET_JAR_SIGNING_KEY_ALIAS", createKeyResponse.keyMetadata().keyId());

            CreateAliasRequest createAliasRequest =
                    CreateAliasRequest.builder()
                            .aliasName(MFA_RESET_JAR_SIGNING_KEY_ALIAS)
                            .targetKeyId(createKeyResponse.keyMetadata().keyId())
                            .build();

            kmsClient.createAlias(createAliasRequest);

            LOG.info("KMS Key alias: {}", MFA_RESET_JAR_SIGNING_KEY_ALIAS);

            // Retrieve the public key of the KMS key
            GetPublicKeyRequest getPublicKeyRequest =
                    GetPublicKeyRequest.builder()
                            .keyId(createKeyResponse.keyMetadata().keyId())
                            .build();

            GetPublicKeyResponse getPublicKeyResponse = kmsClient.getPublicKey(getPublicKeyRequest);

            expectedKid = hashSha256String(getPublicKeyResponse.keyId());

            LOG.info("Retrieved kid: {}", expectedKid);
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        }
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
        var configurationService = new ConfigurationService();
        handler = new MfaResetJarJwkHandler(configurationService);

        var response = makeRequest(Optional.empty(), Map.of(), Map.of());

        assertThat(response, hasStatus(200));

        JsonObject jwk = JsonParser.parseString(response.getBody()).getAsJsonObject();
        JsonArray keys = jwk.get("keys").getAsJsonArray();
        assertEquals(1, keys.size(), "JWKS endpoint must return a single key.");

        checkPublicSigningKeyResponseMeetsADR0030(keys.get(0).getAsJsonObject());
    }

    private static void checkPublicSigningKeyResponseMeetsADR0030(JsonObject key) {
        assertEquals(expectedKid, key.get("kid").getAsString());
        assertEquals(KeyType.EC.getValue(), key.get("kty").getAsString());
        assertEquals(KeyUse.SIGNATURE.getValue(), key.get("use").getAsString());
        assertEquals(Curve.P_256.getName(), key.get("crv").getAsString());
        assertEquals(JWSAlgorithm.ES256.toString(), key.get("alg").getAsString());
    }
}
