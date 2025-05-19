package uk.gov.di.authentication.frontendapi.services;

import com.google.gson.GsonBuilder;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.approvaltests.Approvals;
import org.approvaltests.JsonApprovals;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import uk.gov.di.authentication.frontendapi.exceptions.IPVReverificationServiceException;
import uk.gov.di.authentication.shared.exceptions.MissingEnvVariableException;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.TokenService;
import uk.gov.di.authentication.sharedtest.helper.TestClockHelper;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.INTERNAL_COMMON_SUBJECT_ID;
import static uk.gov.di.authentication.sharedtest.helper.KeyPairHelper.GENERATE_RSA_KEY_PAIR;

class IPVReverificationServiceTest {
    private static final JWSAlgorithm TEST_SIGNING_ALGORITHM = JWSAlgorithm.ES256;
    private static final String TEST_MFA_RESET_SCOPE = "reverification";
    private static final String TEST_STATE_STORAGE_PREFIX = "mfaReset:state:";
    private static final String TEST_STATE_VALUE = "testState";
    public static final State STATE = State.parse(TEST_STATE_VALUE);
    private static final String TEST_CLIENT_SESSION_ID = "journeyId";
    private static final Subject TEST_SUBJECT = new Subject(INTERNAL_COMMON_SUBJECT_ID);
    private static final String TEST_AUDIENCE_CLAIM = "someAud";
    private static final String TEST_ISSUER_CLAIM = "someIssuer";
    private static final String TEST_UUID = "someSuperUniqueUUID";
    private static final String TEST_IPV_AUTHORIZE_URI = "https://some.uri.gov.uk/authorize";
    private static final String TEST_IPV_AUTH_CLIENT_ID = "someClientId";
    private static final String TEST_KEY_ID = "123456";
    private static final String TEST_IPV_JWKS_URL =
            "https://api.identity.test.account.gov.uk/.well-known/jwks.json";
    private static final String TEST_STORAGE_TOKEN =
            "eyJraWQiOiIxZDUwNGFlY2UyOThhMTRkNzRlZTBhMDJiNjc0MGI0MzcyYTFmYWI0MjA2Nzc4ZTQ4NmJhNzI3NzBmZjRiZWI4IiwiYWxnIjoiRVMyNTYifQ.eyJhdWQiOlsiaHR0cHM6Ly9jcmVkZW50aWFsLXN0b3JlLmFjY291bnQuZ292LnVrIiwiaHR0cHM6Ly9pZGVudGl0eS50ZXN0LmFjY291bnQuZ292LnVrIl0sInN1YiI6InVybjpmZGM6Z292LnVrOjIwMjI6VEpMdDNXYWlHa0xoOFVxZWlzSDJ6VktHQVAwIiwic2NvcGUiOiJwcm92aW5nIiwiaXNzIjoiaHR0cHM6Ly9vaWRjLnRlc3QuYWNjb3VudC5nb3YudWsiLCJleHAiOjE3MTgxOTU3NjMsImlhdCI6MTcxODE5NTQ2MywianRpIjoiMWQyZTdmODgtYWIwNy00NWU5LThkYTAtOWEyMzIyMWFhZjM3In0.6MpC8IZbOICVjvf_97ySj6yOO6khQGhkEGHvYB6kXGMroSQgF0z0-Z1EVJi5sVXwmbe4X6eDRTIYtM07xItiMg";
    private static final String TEST_STORAGE_TOKEN_CLAIM =
            "https://vocab.account.gov.uk/v1/storageAccessToken";
    private static final long TEST_SESSION_EXPIRY = 123456;
    private static final String TEST_MFA_CALLBACK_URI = "some.call.back.uri";
    private static final Base64URL TEST_ENCODED_JWS_HEADER =
            new JWSHeader.Builder(TEST_SIGNING_ALGORITHM).keyID(TEST_KEY_ID).build().toBase64URL();
    private static final Base64URL TEST_ENCODED_JWS_SIGNATURE =
            new Base64URL("someVeryLegitSignature");
    private static final KeyPair TEST_KEY_PAIR = GENERATE_RSA_KEY_PAIR();
    private static final RSAPublicKey TEST_PUBLIC_KEY = (RSAPublicKey) TEST_KEY_PAIR.getPublic();
    private static final RSAPrivateKey TEST_PRIVATE_KEY =
            (RSAPrivateKey) TEST_KEY_PAIR.getPrivate();

    private final Json objectMapper = SerializationService.getInstance();
    private final JwtService jwtService = mock(JwtService.class);
    private final NowHelper.NowClock nowClock = TestClockHelper.getInstance();
    private final TokenService tokenService = mock(TokenService.class);
    private final JWKSource<SecurityContext> jwkSource = mock(JWKSource.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final JWTClaimsSet testJwtClaims = constructTestClaimSet();
    private final IPVReverificationService ipvReverificationService =
            new IPVReverificationService(
                    configurationService, nowClock, jwtService, tokenService, jwkSource);
    private SignedJWT testSignedJwt;
    private EncryptedJWT testEncryptedJwt;
    MockedStatic<IdGenerator> mockIdGen;

    IPVReverificationServiceTest() throws MalformedURLException {}

    @BeforeEach
    void testSetup() throws URISyntaxException, ParseException, JOSEException {
        when(tokenService.generateStorageTokenForMfaReset(any()))
                .thenReturn(new BearerAccessToken(TEST_STORAGE_TOKEN));
        when(configurationService.getMfaResetJarSigningKeyId()).thenReturn(TEST_KEY_ID);
        when(configurationService.getStorageTokenClaimName()).thenReturn(TEST_STORAGE_TOKEN_CLAIM);
        when(configurationService.getMfaResetCallbackURI())
                .thenReturn(new URI(TEST_MFA_CALLBACK_URI));
        when(configurationService.getIPVAuthEncryptionPublicKey())
                .thenReturn(constructTestPublicKey());
        when(configurationService.getIPVAuthorisationClientId())
                .thenReturn(TEST_IPV_AUTH_CLIENT_ID);
        when(configurationService.getAuthIssuerClaim()).thenReturn(TEST_ISSUER_CLAIM);
        when(configurationService.getIPVAuthorisationURI())
                .thenReturn(new URI(TEST_IPV_AUTHORIZE_URI));
        when(configurationService.getSessionExpiry()).thenReturn(TEST_SESSION_EXPIRY);
        when(configurationService.getIPVAudience()).thenReturn(TEST_AUDIENCE_CLAIM);
        testSignedJwt =
                new SignedJWT(
                        TEST_ENCODED_JWS_HEADER,
                        Base64URL.encode(testJwtClaims.toString()),
                        TEST_ENCODED_JWS_SIGNATURE);
        testEncryptedJwt = constructTestEncryptedJWT(testSignedJwt);
        when(jwtService.signJWT(any(), any(), any())).thenReturn(testSignedJwt);
        when(jwtService.encryptJWT(any(), any())).thenReturn(testEncryptedJwt);
        mockIdGen = Mockito.mockStatic(IdGenerator.class);
        mockIdGen.when(IdGenerator::generate).thenReturn(TEST_UUID);
    }

    @AfterEach
    void tearDown() {
        mockIdGen.close();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldReturn200WithAuthorizeUrlInBody(boolean isIpvJwksCallEnabled)
            throws JOSEException, ParseException, MalformedURLException, NoSuchAlgorithmException {
        when(configurationService.isIpvJwksCallEnabled()).thenReturn(isIpvJwksCallEnabled);
        if (isIpvJwksCallEnabled) {
            when(configurationService.getIpvJwksUrl()).thenReturn(new URL(TEST_IPV_JWKS_URL));

            when(jwkSource.get(Mockito.any(JWKSelector.class), Mockito.isNull()))
                    .thenReturn(
                            Collections.singletonList(
                                    new RSAKey.Builder(IPVReverificationServiceTest.TEST_PUBLIC_KEY)
                                            .build()));
        }

        IPVReverificationService ipvReverificationService =
                new IPVReverificationService(
                        configurationService, nowClock, jwtService, tokenService, jwkSource);

        try (MockedConstruction<State> mockedState =
                Mockito.mockConstruction(
                        State.class,
                        (mock, context) -> {
                            when(mock.getValue()).thenReturn(TEST_STATE_VALUE);
                        })) {

            String redirectUri =
                    ipvReverificationService.buildIpvReverificationRedirectUri(
                            TEST_SUBJECT, TEST_CLIENT_SESSION_ID, STATE);

            RSAPublicKey expectedPublicKey =
                    new RSAKey.Builder(
                                    (RSAKey)
                                            JWK.parseFromPEMEncodedObjects(
                                                    constructTestPublicKey()))
                            .build()
                            .toRSAPublicKey();

            verify(jwtService)
                    .signJWT(TEST_SIGNING_ALGORITHM, constructTestClaimSet(), TEST_KEY_ID);
            verify(jwtService).encryptJWT(testSignedJwt, expectedPublicKey);
            verify(tokenService).generateStorageTokenForMfaReset(TEST_SUBJECT);

            var expectedUri =
                    TEST_IPV_AUTHORIZE_URI
                            + "?response_type=code"
                            + "&request="
                            + testEncryptedJwt.serialize()
                            + "&client_id="
                            + TEST_IPV_AUTH_CLIENT_ID;

            assertEquals(expectedUri, redirectUri);

            Approvals.settings().allowMultipleVerifyCallsForThisMethod();
            assertClaims(redirectUri);
        }
    }

    @Test
    void shouldThrowIPVReverificationServiceExceptionWhenPublicKeyNotFound() {
        when(configurationService.getIPVAuthEncryptionPublicKey())
                .thenThrow(new MissingEnvVariableException("IPV_PUBLIC_ENCRYPTION_KEY"));

        var exception =
                assertThrows(
                        IPVReverificationServiceException.class,
                        () ->
                                ipvReverificationService.buildIpvReverificationRedirectUri(
                                        TEST_SUBJECT, TEST_CLIENT_SESSION_ID, STATE));

        assertEquals(
                "Missing required environment variable: IPV_PUBLIC_ENCRYPTION_KEY",
                exception.getMessage());
    }

    private JWTClaimsSet constructTestClaimSet() {
        var claimsRequest =
                new OIDCClaimsRequest()
                        .withUserInfoClaimsRequest(
                                new ClaimsSetRequest()
                                        .add(
                                                new ClaimsSetRequest.Entry(TEST_STORAGE_TOKEN_CLAIM)
                                                        .withValues(List.of(TEST_STORAGE_TOKEN))));
        var claimsBuilder =
                new JWTClaimsSet.Builder()
                        .issuer(TEST_ISSUER_CLAIM)
                        .audience(TEST_AUDIENCE_CLAIM)
                        .expirationTime(
                                TestClockHelper.getInstance().nowPlus(3, ChronoUnit.MINUTES))
                        .subject(TEST_SUBJECT.getValue())
                        .issueTime(TestClockHelper.getInstance().now())
                        .jwtID(TEST_UUID)
                        .notBeforeTime(TestClockHelper.getInstance().now())
                        .claim("state", TEST_STATE_VALUE)
                        .claim("govuk_signin_journey_id", TEST_CLIENT_SESSION_ID)
                        .claim("redirect_uri", TEST_MFA_CALLBACK_URI)
                        .claim("client_id", TEST_IPV_AUTH_CLIENT_ID)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", TEST_MFA_RESET_SCOPE)
                        .claim("claims", claimsRequest.toJSONObject());
        return claimsBuilder.build();
    }

    private void assertClaims(String authorizeUri) throws ParseException, JOSEException {
        var jweStartIndex = (TEST_IPV_AUTHORIZE_URI + "?response_type=code" + "&request=").length();
        var jweEndIndex =
                authorizeUri.length() - ("&client_id=" + TEST_IPV_AUTH_CLIENT_ID).length();
        var serializedJWE = authorizeUri.substring(jweStartIndex, jweEndIndex);
        EncryptedJWT redirectUriJWE = EncryptedJWT.parse(serializedJWE);
        redirectUriJWE.decrypt(new RSADecrypter(TEST_PRIVATE_KEY));
        var jarClaimSet = redirectUriJWE.getPayload().toSignedJWT().getJWTClaimsSet();

        assertThat(jarClaimSet.getClaim("sub"), equalTo(TEST_SUBJECT.getValue()));
        assertThat(jarClaimSet.getClaim("scope"), equalTo(TEST_MFA_RESET_SCOPE));
        assertThat(jarClaimSet.getIssuer(), equalTo(TEST_ISSUER_CLAIM));
        assertThat(jarClaimSet.getClaim("aud"), equalTo(List.of(TEST_AUDIENCE_CLAIM)));
        assertThat(
                jarClaimSet.getClaim("govuk_signin_journey_id"), equalTo(TEST_CLIENT_SESSION_ID));
        assertThat(jarClaimSet.getClaim("redirect_uri"), equalTo(TEST_MFA_CALLBACK_URI));
        assertThat(jarClaimSet.getClaim("client_id"), equalTo(TEST_IPV_AUTH_CLIENT_ID));
        assertThat(jarClaimSet.getClaim("response_type"), equalTo(ResponseType.CODE.toString()));

        JsonApprovals.verifyAsJson(jarClaimSet.toJSONObject(), GsonBuilder::serializeNulls);
    }

    private static String constructTestPublicKey() {
        var encodedKey =
                Base64.getMimeEncoder()
                        .encodeToString(IPVReverificationServiceTest.TEST_PUBLIC_KEY.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + encodedKey + "\n-----END PUBLIC KEY-----\n";
    }

    private EncryptedJWT constructTestEncryptedJWT(SignedJWT signedJWT)
            throws ParseException, JOSEException {
        JWEObject jweObject =
                new JWEObject(
                        new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                                .contentType("JWT")
                                .build(),
                        new Payload(signedJWT));
        jweObject.encrypt(new RSAEncrypter(TEST_PUBLIC_KEY));
        return EncryptedJWT.parse(jweObject.serialize());
    }
}
