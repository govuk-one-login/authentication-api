package uk.gov.di.authentication.frontendapi.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import uk.gov.di.authentication.frontendapi.exceptions.JarValidationException;
import uk.gov.di.authentication.shared.configuration.OauthClientConfig;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class JarValidatorTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    // This key is only for use in insecure local testing
    private static final String EC_PRIVATE_KEY =
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSpFQByZAQH3n5lCu0L+foxHzwi/I1RtJ4o8jyTtwj4WhRANCAASyFo4Vo28pL3dLQ7YAqsSBlcxUPZFkq4YeTPS3lxx53aay6jy6I+V3ZYmr3ZGDnR2JRydsa4kXumn2jvfKOvuW";
    private static final String EC_PUBLIC_KEY =
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEshaOFaNvKS93S0O2AKrEgZXMVD2RZKuGHkz0t5cced2msuo8uiPld2WJq92Rg50diUcnbGuJF7pp9o73yjr7lg==";

    // Needs to be parseable but contents are stubbed by the mock JWEDecrypter
    private static final String PLACEHOLDER_JWE =
            "eyJ0eXAiOiJKV0UiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.ZpVOfw61XyBBgsR4CRNRMn2oj_S65pMJO-iaEHpR6QrPcIuD4ysZexolo28vsZyZNR-kfVdw_5CjQanwMS-yw3U3nSUvXUrTs3uco-FSXulIeDYTRbBtQuDyvBMVoos6DyIfC6eBj30GMe5g6DF5KJ1Q0eXQdF0kyM9olg76uYAUqZ5rW52rC_SOHb5_tMj7UbO2IViIStdzLgVfgnJr7Ms4bvG0C8-mk4Otd7m2Km2-DNyGaNuFQSKclAGu7Zgg-qDyhH4V1Z6WUHt79TuG4TxseUr-6oaFFVD23JYSBy7Aypt0321ycq13qcN-PBiOWtumeW5-_CQuHLaPuOc4-w.RO9IB2KcS2hD3dWlKXSreQ.93Ntu3e0vNSYv4hoMwZ3Aw.YRvWo4bwsP_l7dL_29imGg";
    private static final String TEST_JTI = "test-jwt-id";
    private static final String TEST_AUDIENCE = "test-audience";
    private static final String TEST_CLIENT_ID = "test-client-id";
    private static final String TEST_REDIRECT_URI = "https://example.com";
    private static final String TEST_STATE = "af0ifjsldkj";

    @Mock private ConfigurationService configService;
    @Mock private JWEDecrypter jweDecrypter;
    @InjectMocks private JarValidationService jarValidationService;

    private AutoCloseable mocks;

    @BeforeEach
    void setup() {
        mocks = MockitoAnnotations.openMocks(this);
        when(configService.getMaxJarTimeToLiveSeconds()).thenReturn(3600);
        when(configService.getAuthAudience()).thenReturn(URI.create(TEST_AUDIENCE));
        when(configService.getOauthClientConfig())
                .thenReturn(
                        Map.of(
                                TEST_CLIENT_ID,
                                new OauthClientConfig(
                                        TEST_CLIENT_ID,
                                        List.of(TEST_REDIRECT_URI),
                                        EC_PUBLIC_KEY)));
    }

    @AfterEach
    void teardown() throws Exception {
        mocks.close();
    }

    @Test
    void shouldReturnValidClaimsOnValidJarRequest() throws Exception {
        var signedJWT = generateJWT(getValidClaimsSetValues());
        when(jweDecrypter.decrypt(any(), any(), any(), any(), any(), any()))
                .thenReturn(signedJWT.serialize().getBytes(StandardCharsets.UTF_8));

        var claimsSet = jarValidationService.parseAndValidateJar(PLACEHOLDER_JWE, TEST_CLIENT_ID);

        assertEquals(TEST_JTI, claimsSet.getJWTID());
        assertEquals(TEST_REDIRECT_URI, claimsSet.getStringClaim("redirect_uri"));
        assertEquals(Collections.singletonList(TEST_AUDIENCE), claimsSet.getAudience());
    }

    @Test
    void shouldThrowExceptionIfDecryptionFails() throws Exception {
        when(jweDecrypter.decrypt(any(), any(), any(), any(), any(), any()))
                .thenThrow(new JOSEException("Decryption failed!"));

        var thrown =
                assertThrows(
                        JarValidationException.class,
                        () ->
                                jarValidationService.parseAndValidateJar(
                                        PLACEHOLDER_JWE, TEST_CLIENT_ID));
        assertEquals(
                OAuth2Error.INVALID_REQUEST_OBJECT.getCode(), thrown.getErrorObject().getCode());
    }

    @Test
    void shouldFailValidationChecksOnInvalidClientId() throws Exception {
        var signedJWT = generateJWT(getValidClaimsSetValues());
        when(jweDecrypter.decrypt(any(), any(), any(), any(), any(), any()))
                .thenReturn(signedJWT.serialize().getBytes(StandardCharsets.UTF_8));

        var thrown =
                assertThrows(
                        JarValidationException.class,
                        () ->
                                jarValidationService.parseAndValidateJar(
                                        PLACEHOLDER_JWE, "other-client-id"));

        var errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_CLIENT.getHTTPStatusCode(), errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_CLIENT.getCode(), errorObject.getCode());
        assertEquals("Unknown client id was provided", errorObject.getDescription());
    }

    @Test
    void shouldFailValidationChecksOnInvalidAlgorithm() throws Exception {
        var signedJWT = generateJWT(getValidClaimsSetValues());
        var invalidSignedJWT =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .type(JOSEObjectType.JWT)
                                .build()
                                .toBase64URL(),
                        signedJWT.getPayload().toBase64URL(),
                        signedJWT.getSignature());
        when(jweDecrypter.decrypt(any(), any(), any(), any(), any(), any()))
                .thenReturn(invalidSignedJWT.serialize().getBytes(StandardCharsets.UTF_8));

        var thrown =
                assertThrows(
                        JarValidationException.class,
                        () ->
                                jarValidationService.parseAndValidateJar(
                                        PLACEHOLDER_JWE, TEST_CLIENT_ID));

        var errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_REQUEST_OBJECT.getHTTPStatusCode(),
                errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_REQUEST_OBJECT.getCode(), errorObject.getCode());
        assertEquals(
                "Signing algorithm used does not match required algorithm",
                errorObject.getDescription());
    }

    @Test
    void shouldFailValidationChecksOnInvalidJWTSignature() throws Exception {
        var signedJWT = generateJWT(getValidClaimsSetValues());
        var invalidSignedJWT =
                new SignedJWT(
                        signedJWT.getHeader().toBase64URL(),
                        signedJWT.getPayload().toBase64URL(),
                        Base64URL.encode("not-a-signature"));
        when(jweDecrypter.decrypt(any(), any(), any(), any(), any(), any()))
                .thenReturn(invalidSignedJWT.serialize().getBytes(StandardCharsets.UTF_8));

        var thrown =
                assertThrows(
                        JarValidationException.class,
                        () ->
                                jarValidationService.parseAndValidateJar(
                                        PLACEHOLDER_JWE, TEST_CLIENT_ID));
        var errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_REQUEST_OBJECT.getHTTPStatusCode(),
                errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_REQUEST_OBJECT.getCode(), errorObject.getCode());
        assertEquals("JWT signature validation failed", errorObject.getDescription());
    }

    @Test
    void shouldFailValidationChecksOnMissingRequiredClaim() throws Exception {
        var signer = new ECDSASigner(getPrivateKey());
        var claimsSet =
                new JWTClaimsSet.Builder().claim(JWTClaimNames.AUDIENCE, TEST_AUDIENCE).build();
        var signedJWT =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build(),
                        claimsSet);
        signedJWT.sign(signer);
        when(jweDecrypter.decrypt(any(), any(), any(), any(), any(), any()))
                .thenReturn(signedJWT.serialize().getBytes(StandardCharsets.UTF_8));

        var thrown =
                assertThrows(
                        JarValidationException.class,
                        () ->
                                jarValidationService.parseAndValidateJar(
                                        PLACEHOLDER_JWE, TEST_CLIENT_ID));

        var errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_GRANT.getHTTPStatusCode(), errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorObject.getCode());
        assertEquals(
                "JWT missing required claims: [client_id, exp, iat, iss, nbf]",
                thrown.getCause().getMessage());
    }

    @Test
    void shouldFailValidationChecksOnInvalidAudienceClaim() throws Exception {
        var invalidAudienceClaims = getValidClaimsSetValues();
        invalidAudienceClaims.put(JWTClaimNames.AUDIENCE, "invalid-audience");

        var signedJWT = generateJWT(invalidAudienceClaims);
        when(jweDecrypter.decrypt(any(), any(), any(), any(), any(), any()))
                .thenReturn(signedJWT.serialize().getBytes(StandardCharsets.UTF_8));

        var thrown =
                assertThrows(
                        JarValidationException.class,
                        () ->
                                jarValidationService.parseAndValidateJar(
                                        PLACEHOLDER_JWE, TEST_CLIENT_ID));

        var errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_GRANT.getHTTPStatusCode(), errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorObject.getCode());
        assertEquals("JWT audience rejected: [invalid-audience]", thrown.getCause().getMessage());
    }

    @Test
    void shouldFailValidationChecksOnInvalidIssuerClaim() throws Exception {
        var invalidIssuerClaims = getValidClaimsSetValues();
        invalidIssuerClaims.put(JWTClaimNames.ISSUER, "invalid-issuer");
        var signedJWT = generateJWT(invalidIssuerClaims);
        when(jweDecrypter.decrypt(any(), any(), any(), any(), any(), any()))
                .thenReturn(signedJWT.serialize().getBytes(StandardCharsets.UTF_8));

        var thrown =
                assertThrows(
                        JarValidationException.class,
                        () ->
                                jarValidationService.parseAndValidateJar(
                                        PLACEHOLDER_JWE, TEST_CLIENT_ID));

        var errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_GRANT.getHTTPStatusCode(), errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorObject.getCode());
        assertEquals(
                "JWT iss claim has value invalid-issuer, must be test-client-id",
                thrown.getCause().getMessage());
    }

    @Test
    void shouldFailValidationChecksIfClientIdClaimDoesNotMatchParam() throws Exception {
        var claims = getValidClaimsSetValues();
        claims.put("client_id", "invalid-client-id");

        var signedJWT = generateJWT(claims);
        when(jweDecrypter.decrypt(any(), any(), any(), any(), any(), any()))
                .thenReturn(signedJWT.serialize().getBytes(StandardCharsets.UTF_8));

        JarValidationException thrown =
                assertThrows(
                        JarValidationException.class,
                        () ->
                                jarValidationService.parseAndValidateJar(
                                        PLACEHOLDER_JWE, TEST_CLIENT_ID));

        var errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_GRANT.getHTTPStatusCode(), errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorObject.getCode());
        assertEquals(
                "JWT client_id claim has value invalid-client-id, must be test-client-id",
                thrown.getCause().getMessage());
    }

    @Test
    void shouldFailValidationChecksOnExpiredJWT() throws Exception {
        var expiredClaims = getValidClaimsSetValues();
        expiredClaims.put(JWTClaimNames.EXPIRATION_TIME, fifteenMinutesInPast());

        var signedJWT = generateJWT(expiredClaims);
        when(jweDecrypter.decrypt(any(), any(), any(), any(), any(), any()))
                .thenReturn(signedJWT.serialize().getBytes(StandardCharsets.UTF_8));

        var thrown =
                assertThrows(
                        JarValidationException.class,
                        () ->
                                jarValidationService.parseAndValidateJar(
                                        PLACEHOLDER_JWE, TEST_CLIENT_ID));

        var errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_GRANT.getHTTPStatusCode(), errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorObject.getCode());
        assertEquals("Expired JWT", thrown.getCause().getMessage());
    }

    @Test
    void shouldFailValidationChecksOnFutureNbfClaim() throws Exception {
        var notValidYet = getValidClaimsSetValues();
        notValidYet.put(JWTClaimNames.NOT_BEFORE, fifteenMinutesFromNow());

        var signedJWT = generateJWT(notValidYet);
        when(jweDecrypter.decrypt(any(), any(), any(), any(), any(), any()))
                .thenReturn(signedJWT.serialize().getBytes(StandardCharsets.UTF_8));

        var thrown =
                assertThrows(
                        JarValidationException.class,
                        () ->
                                jarValidationService.parseAndValidateJar(
                                        PLACEHOLDER_JWE, TEST_CLIENT_ID));
        var errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_GRANT.getHTTPStatusCode(), errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorObject.getCode());
        assertEquals("JWT before use time", thrown.getCause().getMessage());
    }

    @Test
    void validateRequestJwtShouldFailValidationChecksOnExpiryClaimToFarInFuture() throws Exception {
        var futureClaims = getValidClaimsSetValues();
        futureClaims.put(
                JWTClaimNames.EXPIRATION_TIME, OffsetDateTime.now().plusYears(100).toEpochSecond());

        var signedJWT = generateJWT(futureClaims);
        when(jweDecrypter.decrypt(any(), any(), any(), any(), any(), any()))
                .thenReturn(signedJWT.serialize().getBytes(StandardCharsets.UTF_8));

        var thrown =
                assertThrows(
                        JarValidationException.class,
                        () ->
                                jarValidationService.parseAndValidateJar(
                                        PLACEHOLDER_JWE, TEST_CLIENT_ID));

        var errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_GRANT.getHTTPStatusCode(), errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorObject.getCode());
        assertEquals(
                "The client JWT expiry date has surpassed the maximum allowed ttl value",
                errorObject.getDescription());
    }

    @Test
    void shouldFailValidationChecksOnInvalidRedirectUriClaim() throws Exception {
        var badRedirectClaims = getValidClaimsSetValues();
        badRedirectClaims.put("redirect_uri", "http://invalid-redirect");

        var signedJWT = generateJWT(badRedirectClaims);
        when(jweDecrypter.decrypt(any(), any(), any(), any(), any(), any()))
                .thenReturn(signedJWT.serialize().getBytes(StandardCharsets.UTF_8));

        var thrown =
                assertThrows(
                        JarValidationException.class,
                        () ->
                                jarValidationService.parseAndValidateJar(
                                        PLACEHOLDER_JWE, TEST_CLIENT_ID));

        var errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_GRANT.getHTTPStatusCode(), errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorObject.getCode());
        assertEquals(
                "Invalid redirect_uri claim provided for configured client",
                errorObject.getDescription());
    }

    @Test
    void shouldFailValidationChecksOnParseFailureOfRedirectUri() throws Exception {
        var badRedirectClaims = getValidClaimsSetValues();
        badRedirectClaims.put("redirect_uri", "({[]})./sd-234345////invalid-redirect-uri");

        var signedJWT = generateJWT(badRedirectClaims);
        when(jweDecrypter.decrypt(any(), any(), any(), any(), any(), any()))
                .thenReturn(signedJWT.serialize().getBytes(StandardCharsets.UTF_8));

        var thrown =
                assertThrows(
                        JarValidationException.class,
                        () ->
                                jarValidationService.parseAndValidateJar(
                                        PLACEHOLDER_JWE, TEST_CLIENT_ID));

        var errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_REQUEST_OBJECT.getHTTPStatusCode(),
                errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_REQUEST_OBJECT.getCode(), errorObject.getCode());
        assertEquals(
                "Failed to parse JWT claim set in order to access redirect_uri claim",
                errorObject.getDescription());
    }

    private SignedJWT generateJWT(Map<String, Object> claimsSetValues) throws Exception {
        var signer = new ECDSASigner(getPrivateKey());

        var signedJWT =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build(),
                        generateClaimsSet(claimsSetValues));
        signedJWT.sign(signer);

        return signedJWT;
    }

    private Map<String, Object> getValidClaimsSetValues() {
        var validClaims = new HashMap<String, Object>();
        validClaims.put(JWTClaimNames.JWT_ID, TEST_JTI);
        validClaims.put(JWTClaimNames.EXPIRATION_TIME, fifteenMinutesFromNow());
        validClaims.put(JWTClaimNames.ISSUED_AT, OffsetDateTime.now().toEpochSecond());
        validClaims.put(JWTClaimNames.NOT_BEFORE, OffsetDateTime.now().toEpochSecond());
        validClaims.put(JWTClaimNames.AUDIENCE, TEST_AUDIENCE);
        validClaims.put(JWTClaimNames.ISSUER, TEST_CLIENT_ID);
        validClaims.put("client_id", TEST_CLIENT_ID);
        validClaims.put("redirect_uri", TEST_REDIRECT_URI);
        validClaims.put("state", TEST_STATE);
        return validClaims;
    }

    private JWTClaimsSet generateClaimsSet(Map<String, Object> claimsSetValues) throws Exception {
        return JWTClaimsSet.parse(OBJECT_MAPPER.writeValueAsString(claimsSetValues));
    }

    private ECPrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY)));
    }

    private static long fifteenMinutesFromNow() {
        return Instant.now().plusSeconds(15 * 60).getEpochSecond();
    }

    private static long fifteenMinutesInPast() {
        return Instant.now().minusSeconds(15 * 60).getEpochSecond();
    }
}
