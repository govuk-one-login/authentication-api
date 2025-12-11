package uk.gov.di.orchestration.shared.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.Nonce;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.InvokeRequest;
import software.amazon.awssdk.services.lambda.model.InvokeResponse;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.PublicKeySource;
import uk.gov.di.orchestration.shared.exceptions.ClientSignatureValidationException;
import uk.gov.di.orchestration.shared.exceptions.JwksException;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.utils.KeyPairUtils.generateRsaKeyPair;

// QualityGateUnitTest
class ClientSignatureValidationServiceTest {

    private static final String REDIRECT_URI = "https://localhost:8080";
    private static final ClientID CLIENT_ID = new ClientID("test-id");
    private static final URI OIDC_BASE_URI = URI.create("https://localhost");
    private static final URI TOKEN_URI = URI.create("https://localhost/token");
    private static final URI AUTHORIZE_URI = URI.create("https://localhost/authorize");

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final OidcAPI oidcAPI = mock(OidcAPI.class);
    private final RpPublicKeyCacheService rpPublicKeyCacheService =
            mock(RpPublicKeyCacheService.class);
    private final LambdaClient lambdaClient = mock(LambdaClient.class);
    private ClientSignatureValidationService clientSignatureValidationService;

    private ClientRegistry client;
    private KeyPair keyPair;

    @BeforeEach
    void setup() {
        when(oidcAPI.tokenURI()).thenReturn(TOKEN_URI);
        when(oidcAPI.getIssuerURI()).thenReturn(OIDC_BASE_URI);
        keyPair = generateRsaKeyPair();
    }

    @Nested
    class StaticPublicKeySource {

        @BeforeEach
        void setup() {
            client = generateClientWithStaticPublicKeySource(keyPair.getPublic());
            clientSignatureValidationService =
                    new ClientSignatureValidationService(
                            configurationService, rpPublicKeyCacheService, lambdaClient, oidcAPI);
        }

        // QualityGateRegressionTest
        @Test
        void shouldSuccessfullyReturnWhenValidatingValidSignedJWT() {
            var signedJWT = generateSignedJWT(keyPair.getPrivate());

            assertDoesNotThrow(() -> clientSignatureValidationService.validate(signedJWT, client));
        }

        // QualityGateRegressionTest
        @Test
        void shouldSuccessfullyReturnWhenValidatingValidPrivateKeyJWT() {
            var privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());

            assertDoesNotThrow(
                    () ->
                            clientSignatureValidationService.validateTokenClientAssertion(
                                    privateKeyJWT, client));
        }

        // QualityGateRegressionTest
        @Test
        void shouldSuccessfullyReturnWhenValidatingPrivateKeyJWTWithIssuerAud() {
            var privateKeyJWT =
                    generatePrivateKeyJWT(keyPair.getPrivate(), Optional.of(OIDC_BASE_URI));

            assertDoesNotThrow(
                    () ->
                            clientSignatureValidationService.validateTokenClientAssertion(
                                    privateKeyJWT, client));
        }

        // QualityGateRegressionTest
        @Test
        void shouldThrowWhenInvalidAudProvided() throws URISyntaxException {
            var privateKeyJWT =
                    generatePrivateKeyJWT(
                            keyPair.getPrivate(),
                            Optional.of(new URI("https://example.com/token")));

            assertThrows(
                    ClientSignatureValidationException.class,
                    () ->
                            clientSignatureValidationService.validateTokenClientAssertion(
                                    privateKeyJWT, client));
        }

        // QualityGateRegressionTest
        @Test
        void shouldThrowExceptionWhenValidatingInvalidSignedJWT() {
            var keyPair2 = generateRsaKeyPair();
            var signedJWT = generateSignedJWT(keyPair2.getPrivate());

            assertThrows(
                    ClientSignatureValidationException.class,
                    () -> clientSignatureValidationService.validate(signedJWT, client));
        }

        // QualityGateRegressionTest
        @Test
        void shouldThrowExceptionWhenValidatingInvalidPrivateKeyJWT() {
            var keyPair2 = generateRsaKeyPair();
            var privateKeyJWT = generatePrivateKeyJWT(keyPair2.getPrivate());

            assertThrows(
                    ClientSignatureValidationException.class,
                    () ->
                            clientSignatureValidationService.validateTokenClientAssertion(
                                    privateKeyJWT, client));
        }

        // QualityGateRegressionTest
        @Test
        void shouldThrowExceptionWhenPublicKeySourceIsStaticButPublicKeyIsNull() {
            var client = generateClientWithStaticPublicKeySourceAndNullPublicKey();
            var signedJWT = generateSignedJWT(keyPair.getPrivate());

            assertThrows(
                    ClientSignatureValidationException.class,
                    () -> clientSignatureValidationService.validate(signedJWT, client));
        }
    }

    @Nested
    class JwksPublicKeySource {

        @BeforeEach
        void setup() {
            client = generateClientWithJwksPublicKeySource();
            clientSignatureValidationService =
                    new ClientSignatureValidationService(
                            configurationService, rpPublicKeyCacheService, lambdaClient, oidcAPI);
        }

        // QualityGateRegressionTest
        @Test
        void shouldSuccessfullyReturnWhenValidatingValidSignedJWT() {
            InvokeResponse response = generateFetchJwksLambdaValidResponse(keyPair.getPublic());
            when(lambdaClient.invoke((InvokeRequest) ArgumentMatchers.any())).thenReturn(response);
            var signedJWT = generateSignedJWT(keyPair.getPrivate());

            assertDoesNotThrow(() -> clientSignatureValidationService.validate(signedJWT, client));
        }

        // QualityGateRegressionTest
        @Test
        void shouldThrowExceptionWhenFetchJwksHandlerReturnsError() {
            InvokeResponse response = generateFetchJwksLambdaErrorResponse();
            when(lambdaClient.invoke((InvokeRequest) ArgumentMatchers.any())).thenReturn(response);
            var signedJWT = generateSignedJWT(keyPair.getPrivate());

            assertThrows(
                    JwksException.class,
                    () -> clientSignatureValidationService.validate(signedJWT, client));
        }

        // QualityGateRegressionTest
        @Test
        void shouldSuccessfullyReturnWhenValidatingValidPrivateKeyJWT() {
            InvokeResponse response = generateFetchJwksLambdaValidResponse(keyPair.getPublic());
            when(lambdaClient.invoke((InvokeRequest) ArgumentMatchers.any())).thenReturn(response);
            var privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());

            assertDoesNotThrow(
                    () ->
                            clientSignatureValidationService.validateTokenClientAssertion(
                                    privateKeyJWT, client));
        }

        // QualityGateRegressionTest
        @Test
        void shouldThrowExceptionWhenValidatingInvalidSignedJWT() {
            var keyPair2 = generateRsaKeyPair();
            InvokeResponse response = generateFetchJwksLambdaValidResponse(keyPair2.getPublic());
            when(lambdaClient.invoke((InvokeRequest) ArgumentMatchers.any())).thenReturn(response);
            var signedJWT = generateSignedJWT(keyPair.getPrivate());

            assertThrows(
                    ClientSignatureValidationException.class,
                    () -> clientSignatureValidationService.validate(signedJWT, client));
        }

        // QualityGateRegressionTest
        @Test
        void shouldThrowExceptionWhenValidatingInvalidPrivateKeyJWT() {
            var keyPair2 = generateRsaKeyPair();
            InvokeResponse response = generateFetchJwksLambdaValidResponse(keyPair2.getPublic());
            when(lambdaClient.invoke((InvokeRequest) ArgumentMatchers.any())).thenReturn(response);
            var privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());

            assertThrows(
                    ClientSignatureValidationException.class,
                    () ->
                            clientSignatureValidationService.validateTokenClientAssertion(
                                    privateKeyJWT, client));
        }
    }

    private static SignedJWT generateSignedJWT(PrivateKey privateKey) {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", "openid")
                        .claim("nonce", new Nonce().getValue())
                        .claim("state", new State().toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("vtr", List.of("P0.Cl"))
                        .issuer(CLIENT_ID.getValue())
                        .build();
        JWSHeader jwsHeader = new JWSHeader.Builder(RS256).keyID("some-key-id").build();
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        var signer = new RSASSASigner(privateKey);
        try {
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        return signedJWT;
    }

    private static PrivateKeyJWT generatePrivateKeyJWT(PrivateKey privateKey) {
        return generatePrivateKeyJWT(privateKey, Optional.empty());
    }

    private static PrivateKeyJWT generatePrivateKeyJWT(
            PrivateKey privateKey, Optional<URI> audience) {
        try {
            return new PrivateKeyJWT(
                    new ClientID(CLIENT_ID),
                    audience.orElse(TOKEN_URI),
                    JWSAlgorithm.RS256,
                    privateKey,
                    "12345",
                    null);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    private InvokeResponse generateFetchJwksLambdaValidResponse(PublicKey publicKey) {
        JWK jwk =
                new RSAKey.Builder((RSAPublicKey) publicKey)
                        .keyID("12345")
                        .keyUse(KeyUse.SIGNATURE)
                        .algorithm(RS256)
                        .build();
        String escapedJwkStr = jwk.toString().replace("\"", "\\\"");
        escapedJwkStr = "\"" + escapedJwkStr + "\"";
        SdkBytes sdkBytes = SdkBytes.fromUtf8String(escapedJwkStr);
        return InvokeResponse.builder().payload(sdkBytes).build();
    }

    private InvokeResponse generateFetchJwksLambdaErrorResponse() {
        SdkBytes sdkBytes = SdkBytes.fromUtf8String("error");
        return InvokeResponse.builder().payload(sdkBytes).build();
    }

    private static ClientRegistry generateClientWithStaticPublicKeySource(PublicKey publicKey) {
        var encodedPublicKey = Base64.getMimeEncoder().encodeToString(publicKey.getEncoded());
        return new ClientRegistry()
                .withClientID(CLIENT_ID.getValue())
                .withPublicKeySource(PublicKeySource.STATIC.getValue())
                .withPublicKey(encodedPublicKey);
    }

    private static ClientRegistry generateClientWithJwksPublicKeySource() {
        return new ClientRegistry()
                .withClientID(CLIENT_ID.getValue())
                .withPublicKeySource(PublicKeySource.JWKS.getValue())
                .withJwksUrl("https://some-url");
    }

    private static ClientRegistry generateClientWithStaticPublicKeySourceAndNullPublicKey() {
        return new ClientRegistry()
                .withClientID(CLIENT_ID.getValue())
                .withPublicKeySource(PublicKeySource.STATIC.getValue())
                .withPublicKey(null);
    }
}
