package uk.gov.di.authentication.external.validators;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.id.Audience;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.exceptions.TokenAuthInvalidException;
import uk.gov.di.authentication.shared.services.RemoteJwksService;
import uk.gov.di.authentication.sharedtest.helper.JwtHelper;

import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TokenRequestValidatorTest {
    private static final String VALID_REDIRECT_URI = "https://redirect-uri.co.uk";
    private static final String VALID_CLIENT_ID = "client-id";
    private static final RemoteJwksService authJwksService = mock(RemoteJwksService.class);
    private final TokenRequestValidator validator =
            new TokenRequestValidator(VALID_REDIRECT_URI, VALID_CLIENT_ID);

    @Nested
    class ValidatePlaintextParamsTests {
        @Test
        void shouldReturnInvalidRequestCodeIfGivenNullInput() {
            Optional<ErrorObject> result = validator.validatePlaintextParams(null);

            assertEquals(OAuth2Error.INVALID_REQUEST_CODE, result.get().getCode());
            assertEquals("Request requires query parameters", result.get().getDescription());
        }

        @Test
        void shouldReturnInvalidRequestCodeIfGivenNoGrantType() {
            Optional<ErrorObject> result =
                    validator.validatePlaintextParams(Map.of("key", "value"));

            assertEquals(OAuth2Error.INVALID_REQUEST_CODE, result.get().getCode());
            assertEquals("Request is missing grant_type parameter", result.get().getDescription());
        }

        @Test
        void shouldReturnInvalidRequestCodeIfGivenGrantTypeButOfInvalidValue() {
            Optional<ErrorObject> result =
                    validator.validatePlaintextParams(Map.of("grant_type", "value"));

            assertEquals(OAuth2Error.INVALID_REQUEST_CODE, result.get().getCode());
            assertEquals("Request has invalid grant_type parameter", result.get().getDescription());
        }

        @Test
        void shouldReturnInvalidRequestCodeIfGivenValidGrantTypeButNoCode() {
            Optional<ErrorObject> result =
                    validator.validatePlaintextParams(Map.of("grant_type", "authorization_code"));

            assertEquals(OAuth2Error.INVALID_REQUEST_CODE, result.get().getCode());
            assertEquals("Request is missing code parameter", result.get().getDescription());
        }

        @Test
        void shouldReturnInvalidRequestCodeIfGivenValidGrantTypeAndCodeButNoRedirectUri() {
            Optional<ErrorObject> result =
                    validator.validatePlaintextParams(
                            Map.of("grant_type", "authorization_code", "code", "value"));

            assertEquals(OAuth2Error.INVALID_REQUEST_CODE, result.get().getCode());
            assertEquals(
                    "Request is missing redirect_uri parameter", result.get().getDescription());
        }

        @Test
        void
                shouldReturnInvalidRequestCodeIfGivenValidGrantTypeAndCodeAndRedirectUriOtherThanPermittedRedirectUri() {
            Optional<ErrorObject> result =
                    validator.validatePlaintextParams(
                            Map.of(
                                    "grant_type",
                                    "authorization_code",
                                    "code",
                                    "value",
                                    "redirect_uri",
                                    "value"));

            assertEquals(OAuth2Error.INVALID_REQUEST_CODE, result.get().getCode());
            assertEquals(
                    "Request redirect_uri is not the permitted redirect_uri",
                    result.get().getDescription());
        }

        @Test
        void
                shouldReturnInvalidRequestCodeIfGivenValidGrantTypeAndCodeAndPermittedRedirectButNoClientId() {
            Optional<ErrorObject> result =
                    validator.validatePlaintextParams(
                            Map.of(
                                    "grant_type",
                                    "authorization_code",
                                    "code",
                                    "value",
                                    "redirect_uri",
                                    VALID_REDIRECT_URI));

            assertEquals(OAuth2Error.INVALID_REQUEST_CODE, result.get().getCode());
            assertEquals("Request is missing client_id parameter", result.get().getDescription());
        }

        @Test
        void
                shouldReturnInvalidRequestCodeIfGivenValidGrantTypeAndCodeAndPermittedRedirectButInvalidClientId() {
            Optional<ErrorObject> result =
                    validator.validatePlaintextParams(
                            Map.of(
                                    "grant_type",
                                    "authorization_code",
                                    "code",
                                    "value",
                                    "redirect_uri",
                                    VALID_REDIRECT_URI,
                                    "client_id",
                                    "value"));

            assertEquals(OAuth2Error.INVALID_REQUEST_CODE, result.get().getCode());
            assertEquals(
                    "Request client_id is not the permitted client_id",
                    result.get().getDescription());
        }

        @Test
        void
                shouldReturnNoInvalidRequestCodeIfGivenValidGrantTypeAndCodeAndPermittedRedirectUriAndClientId() {
            Optional<ErrorObject> result =
                    validator.validatePlaintextParams(
                            Map.of(
                                    "grant_type",
                                    "authorization_code",
                                    "code",
                                    "value",
                                    "redirect_uri",
                                    VALID_REDIRECT_URI,
                                    "client_id",
                                    VALID_CLIENT_ID));

            assertEquals(Optional.empty(), result);
        }
    }

    @Nested
    class ValidatePrivateKeyJwtAuthTests {
        private static final Audience AUDIENCE = new Audience("https://example.com/resource");
        private static final Set<Audience> EXPECTED_AUDIENCE =
                Set.of(AUDIENCE, new Audience("https://test.com/resource"));
        private static String validPublicKeyAsX509String;
        private static String alternateEcKeyAsX509String;
        private static String rsaPublicKeyAsX509String;
        private static String validRequestBodyValidSignature;
        private static String validRequestBodyInvalidSignature;
        private static String validRequestBodyRsaSignature;
        private static final String EC_KEY_ID = "ec-key";
        private static final String ALTERNATIVE_EC_KEY_ID = "alternative-ec-key";
        private static final String RSA_KEY_ID = "rsa-key";

        @BeforeAll
        static void init() throws JOSEException, ParseException {
            String validClientAssertionPayload =
                    getClientAssertionPayload(
                            AUDIENCE.getValue(),
                            "matching-random",
                            "matching-random",
                            9999999999L,
                            "jti",
                            0L);

            ECKey validKeyPair = new ECKeyGenerator(Curve.P_256).keyID(EC_KEY_ID).generate();
            X509EncodedKeySpec x509EncodedKeySpec =
                    new X509EncodedKeySpec(validKeyPair.toPublicKey().getEncoded());
            byte[] x509EncodedPublicKey = x509EncodedKeySpec.getEncoded();
            validPublicKeyAsX509String = Base64.getEncoder().encodeToString(x509EncodedPublicKey);
            String clientAssertionValidKeySignature =
                    JwtHelper.jsonToSignedJwt(validClientAssertionPayload, validKeyPair);
            validRequestBodyValidSignature =
                    getValidRequestBodyWithClientAssertion(clientAssertionValidKeySignature);

            ECKey alternateEcKeyPair =
                    new ECKeyGenerator(Curve.P_256).keyID(ALTERNATIVE_EC_KEY_ID).generate();
            String clientAssertionInvalidEcKeySignature =
                    JwtHelper.jsonToSignedJwt(validClientAssertionPayload, alternateEcKeyPair);
            X509EncodedKeySpec alternatex509EncodedKeySpec =
                    new X509EncodedKeySpec(validKeyPair.toPublicKey().getEncoded());
            byte[] alternatex509EncodedPublicKey = alternatex509EncodedKeySpec.getEncoded();

            alternateEcKeyAsX509String =
                    Base64.getEncoder().encodeToString(alternatex509EncodedPublicKey);
            validRequestBodyInvalidSignature =
                    getValidRequestBodyWithClientAssertion(clientAssertionInvalidEcKeySignature);

            RSAKey rsaKeyPair = new RSAKeyGenerator(2048).keyID(RSA_KEY_ID).generate();
            X509EncodedKeySpec x509EncodedKeySpecRsa =
                    new X509EncodedKeySpec(rsaKeyPair.toPublicKey().getEncoded());
            byte[] x509EncodedPublicKeyRsa = x509EncodedKeySpecRsa.getEncoded();
            rsaPublicKeyAsX509String = Base64.getEncoder().encodeToString(x509EncodedPublicKeyRsa);
            JWSSigner rsaSigner = new RSASSASigner(rsaKeyPair.toRSAPrivateKey());
            String clientAssertionRsaKeySignature =
                    JwtHelper.jsonToSignedJwt(
                            validClientAssertionPayload,
                            rsaSigner,
                            JWSAlgorithm.PS256,
                            rsaKeyPair.getKeyID());
            validRequestBodyRsaSignature =
                    getValidRequestBodyWithClientAssertion(clientAssertionRsaKeySignature);
            when(authJwksService.retrieveJwkFromURLWithKeyId(EC_KEY_ID))
                    .thenReturn(validKeyPair.toPublicJWK());
            when(authJwksService.retrieveJwkFromURLWithKeyId(ALTERNATIVE_EC_KEY_ID))
                    .thenReturn(alternateEcKeyPair.toPublicJWK());
            when(authJwksService.retrieveJwkFromURLWithKeyId(RSA_KEY_ID))
                    .thenReturn(rsaKeyPair.toPublicJWK());
        }

        static Stream<Arguments> validationTestData() {
            return Stream.of(
                    arguments(
                            validRequestBodyRsaSignature,
                            OAuth2Error.INVALID_CLIENT_CODE,
                            "Client authentication failed",
                            rsaPublicKeyAsX509String),
                    arguments(
                            validRequestBodyInvalidSignature,
                            OAuth2Error.INVALID_CLIENT_CODE,
                            "Client authentication failed",
                            validPublicKeyAsX509String));
        }

        @ParameterizedTest
        @MethodSource("validationTestData")
        void shouldThrowTokenAuthInvalidExceptionInAllValidationErrorScenarios(
                String requestBody,
                String expectedErrorCode,
                String expectedErrorDescription,
                String orchStubPublicKey) {
            TokenAuthInvalidException exception =
                    assertThrows(
                            TokenAuthInvalidException.class,
                            () ->
                                    validator.validatePrivateKeyJwtClientAuth(
                                            PrivateKeyJWT.parse(requestBody),
                                            EXPECTED_AUDIENCE,
                                            List.of(orchStubPublicKey)));

            assertEquals(expectedErrorCode, exception.getErrorObject().getCode());
            assertEquals(expectedErrorDescription, exception.getErrorObject().getDescription());
        }

        @Test
        void shouldThrowExceptionIfNoKeysAvailableToVerifySignature() throws Exception {
            doThrow(new KeySourceException("No key found"))
                    .when(authJwksService)
                    .retrieveJwkFromURLWithKeyId(anyString());
            assertThrows(
                    TokenAuthInvalidException.class,
                    () ->
                            validator.validatePrivateKeyJwtClientAuth(
                                    PrivateKeyJWT.parse(validRequestBodyValidSignature),
                                    EXPECTED_AUDIENCE,
                                    List.of()));
        }

        @Test
        void
                shouldNotThrowAnyExceptionsIfValidPublicKeyIsUsedToSignValidClientAssertionAsPartOfValidRequestBody() {
            assertDoesNotThrow(
                    () ->
                            validator.validatePrivateKeyJwtClientAuth(
                                    PrivateKeyJWT.parse(validRequestBodyValidSignature),
                                    EXPECTED_AUDIENCE,
                                    Collections.singletonList(validPublicKeyAsX509String)));
        }

        @Test
        void
                shouldNotThrowAnyExceptionsIfValidPublicKeyIsUsedToSignValidClientAssertionAsPartOfValidRequestBodyWithStub() {
            assertDoesNotThrow(
                    () ->
                            validator.validatePrivateKeyJwtClientAuth(
                                    PrivateKeyJWT.parse(validRequestBodyValidSignature),
                                    EXPECTED_AUDIENCE,
                                    List.of(
                                            validPublicKeyAsX509String,
                                            alternateEcKeyAsX509String)));
        }

        @Test
        void
                shouldNotThrowAnyExceptionsIfValidPublicKeyIsUsedToSignValidClientAssertionAsPartOfValidRequestBodyWhenUsingJwks() {
            assertDoesNotThrow(
                    () ->
                            validator.validatePrivateKeyJwtClientAuth(
                                    PrivateKeyJWT.parse(validRequestBodyValidSignature),
                                    EXPECTED_AUDIENCE,
                                    List.of(alternateEcKeyAsX509String)));
        }

        @Test
        void
                shouldNotThrowAnyExceptionsIfValidSignatureUsedWhenNoKeyFoundOnJwksEndpointButStubKeyPresent()
                        throws Exception {
            doThrow(new KeySourceException("No key found"))
                    .when(authJwksService)
                    .retrieveJwkFromURLWithKeyId(anyString());
            assertDoesNotThrow(
                    () ->
                            validator.validatePrivateKeyJwtClientAuth(
                                    PrivateKeyJWT.parse(validRequestBodyValidSignature),
                                    EXPECTED_AUDIENCE,
                                    List.of(alternateEcKeyAsX509String)));
        }
    }

    private static String getValidRequestBodyWithClientAssertion(String clientAssertion) {
        return "code=vC-WxcXDLoOHaJN0YvPB0IwG2LiT1ekSVRSccwubwlI"
                + "&grant_type=authorization_code"
                + "&redirect_uri=https://redirect.uri.com/redirect"
                + "&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"
                + "&client_assertion="
                + clientAssertion;
    }

    private static String getClientAssertionPayload(
            String audience,
            String issuer,
            String subject,
            long expiry,
            String jti,
            long issuedAt) {
        return "{\n"
                + "  \"aud\":\""
                + audience
                + "\",\n"
                + "  \"iss\":\""
                + issuer
                + "\",\n"
                + "  \"sub\":\""
                + subject
                + "\",\n"
                + "  \"exp\":"
                + expiry
                + ",\n"
                + "  \"jti\":\""
                + jti
                + "\",\n"
                + "  \"iat\":"
                + issuedAt
                + "\n"
                + "}";
    }
}
