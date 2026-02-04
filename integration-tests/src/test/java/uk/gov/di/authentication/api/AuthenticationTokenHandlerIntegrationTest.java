package uk.gov.di.authentication.api;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.external.lambda.TokenHandler;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AccessTokenStoreExtension;
import uk.gov.di.authentication.sharedtest.extensions.AuthCodeExtension;
import uk.gov.di.authentication.sharedtest.extensions.JwksExtension;
import uk.gov.di.authentication.sharedtest.extensions.SqsQueueExtension;
import uk.gov.di.authentication.sharedtest.extensions.TokenSigningExtension;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.spec.X509EncodedKeySpec;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static uk.gov.di.authentication.external.domain.AuthExternalApiAuditableEvent.AUTH_TOKEN_SENT_TO_ORCHESTRATION;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.shared.helpers.TxmaAuditHelper.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsSubmittedWithMatchingNames;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthenticationTokenHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    public static final String CLIENT_SESSION_ID = "some-client-session-id";
    public static final String VALID_AUTH_CODE = "valid-auth-code";
    public static final String INVALID_AUTH_CODE = "invalid-auth-code";
    private static final String ORCH_CLIENT_ID = "orch-client-id";
    private static final URI ORCH_REDIRECT_URI = URI.create("http://localhost/redirect");
    private static final URI AUTH_BACKEND_URI = URI.create("http://auth-backend");
    private static final Subject TEST_SUBJECT = new Subject();
    private static final List<String> TEST_CLAIMS = List.of("test-claim-1");
    private static final String TEST_SECTOR_IDENTIFIER = "sectorIdentifier";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_PASSWORD = "password-1";
    private static final String TEST_JOURNEY_ID = "client-session-id";
    public static final String ENCODED_DEVICE_DETAILS =
            "YTtKVSlub1YlOSBTeEI4J3pVLVd7Jjl8VkBfREs2N3clZmN+fnU7fXNbcTJjKyEzN2IuUXIgMGttV058fGhUZ0xhenZUdldEblB8SH18XypwXUhWPXhYXTNQeURW%";
    private static final ECKey STUB_KEY_PAIR;
    private static final String STUB_PUBLIC_KEY;

    static {
        try {
            STUB_KEY_PAIR = new ECKeyGenerator(Curve.P_256).generate();
            X509EncodedKeySpec stubX509EncodedKeySpec =
                    new X509EncodedKeySpec(STUB_KEY_PAIR.toPublicKey().getEncoded());
            byte[] stubX509EncodedPublicKey = stubX509EncodedKeySpec.getEncoded();
            STUB_PUBLIC_KEY = Base64.getEncoder().encodeToString(stubX509EncodedPublicKey);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    @RegisterExtension
    protected static final AuthCodeExtension authCodeStoreExtension = new AuthCodeExtension(180);

    @RegisterExtension
    protected static final AccessTokenStoreExtension accessTokenStoreExtension =
            new AccessTokenStoreExtension(180);

    @RegisterExtension protected static final JwksExtension authJwksExtension = new JwksExtension();

    @BeforeEach
    void setup() throws JOSEException {
        var configurationService =
                new AuthenticationTokenHandlerIntegrationTest.TestConfigurationService(
                        notificationsQueue, tokenSigner, docAppPrivateKeyJwtSigner);

        handler = new TokenHandler(configurationService);

        userStore.signUp(TEST_EMAIL_ADDRESS, TEST_PASSWORD, TEST_SUBJECT);

        authCodeStoreExtension.saveAuthCode(
                TEST_SUBJECT.getValue(),
                VALID_AUTH_CODE,
                TEST_CLAIMS,
                false,
                TEST_SECTOR_IDENTIFIER,
                false,
                TEST_JOURNEY_ID);

        txmaAuditQueue.clear();
    }

    private static Stream<Arguments> signatureVerificationMethods() {
        return Stream.of(
                arguments(named("Using JWKS endpoint", true), named("signing with stub key", true)),
                arguments(
                        named("Using JWKS endpoint", true), named("signing with JWKS key", false)),
                arguments(
                        named("Using hardcoded key", false), named("signing with stub key", true)),
                arguments(
                        named("Using hardcoded key", false),
                        named("signing with hardcoded key", false)));
    }

    @ParameterizedTest
    @MethodSource("signatureVerificationMethods")
    void
            shouldGenerateASuccessfulTokenResponseWhenPresentedWithAValidAuthCodeAndSetCodeStoreFlagToUsed(
                    boolean useAuthJwks, boolean signWithOrchStubKey)
                    throws ParseException, JOSEException {
        if (useAuthJwks) {
            authJwksExtension.init(new JWKSet(EC_KEY_PAIR.toPublicJWK()));
        }
        var configurationService =
                new AuthenticationTokenHandlerIntegrationTest.TestConfigurationService(
                        notificationsQueue,
                        tokenSigner,
                        docAppPrivateKeyJwtSigner,
                        useAuthJwks,
                        signWithOrchStubKey ? Optional.of(STUB_PUBLIC_KEY) : Optional.empty());
        handler = new TokenHandler(configurationService);

        Map<String, List<String>> baseParams =
                baseTokenRequestParamsWithoutClientAssertion(VALID_AUTH_CODE);
        Map<String, List<String>> privateKeyJWT =
                privateKeyJWTParams(signWithOrchStubKey ? STUB_KEY_PAIR : EC_KEY_PAIR);
        baseParams.putAll(privateKeyJWT);
        var requestBody = URLUtils.serializeParameters(baseParams);

        var response =
                makeRequest(
                        Optional.of(requestBody),
                        Map.ofEntries(
                                Map.entry("Content-Type", "application/x-www-form-urlencoded"),
                                Map.entry(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS)),
                        new HashMap<>());

        assertThat(response, hasStatus(200));

        String responseBody = response.getBody();
        HTTPResponse httpResponse = new HTTPResponse(200);
        httpResponse.setContent(responseBody);
        httpResponse.setContentType(response.getHeaders().get("Content-Type"));
        TokenResponse tokenResponse = TokenResponse.parse(httpResponse);
        assertFalse(
                tokenResponse
                        .toSuccessResponse()
                        .getTokens()
                        .getBearerAccessToken()
                        .getValue()
                        .isEmpty());

        var authCodeStorePostHanderExecution = authCodeStoreExtension.getAuthCode(VALID_AUTH_CODE);
        assertTrue(authCodeStorePostHanderExecution.isPresent());
        assertTrue(authCodeStorePostHanderExecution.get().isHasBeenUsed());

        assertTxmaAuditEventsSubmittedWithMatchingNames(
                txmaAuditQueue, List.of(AUTH_TOKEN_SENT_TO_ORCHESTRATION));
    }

    @Test
    void
            shouldGenerateASuccessfulTokenResponseWhenRequestIsSignedByStubKeyAndNoKeysExistOnJwksEndpoint()
                    throws Exception {
        authJwksExtension.init(new JWKSet());
        var configurationService =
                new AuthenticationTokenHandlerIntegrationTest.TestConfigurationService(
                        notificationsQueue,
                        tokenSigner,
                        docAppPrivateKeyJwtSigner,
                        true,
                        Optional.of(STUB_PUBLIC_KEY));
        handler = new TokenHandler(configurationService);

        Map<String, List<String>> baseParams =
                baseTokenRequestParamsWithoutClientAssertion(VALID_AUTH_CODE);
        Map<String, List<String>> privateKeyJWT = privateKeyJWTParams(STUB_KEY_PAIR);
        baseParams.putAll(privateKeyJWT);
        var requestBody = URLUtils.serializeParameters(baseParams);

        var response =
                makeRequest(
                        Optional.of(requestBody),
                        Map.ofEntries(
                                Map.entry("Content-Type", "application/x-www-form-urlencoded"),
                                Map.entry(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS)),
                        new HashMap<>());

        assertThat(response, hasStatus(200));

        String responseBody = response.getBody();
        HTTPResponse httpResponse = new HTTPResponse(200);
        httpResponse.setContent(responseBody);
        httpResponse.setContentType(response.getHeaders().get("Content-Type"));
        TokenResponse tokenResponse = TokenResponse.parse(httpResponse);
        assertFalse(
                tokenResponse
                        .toSuccessResponse()
                        .getTokens()
                        .getBearerAccessToken()
                        .getValue()
                        .isEmpty());

        var authCodeStorePostHanderExecution = authCodeStoreExtension.getAuthCode(VALID_AUTH_CODE);
        assertTrue(authCodeStorePostHanderExecution.isPresent());
        assertTrue(authCodeStorePostHanderExecution.get().isHasBeenUsed());

        assertTxmaAuditEventsSubmittedWithMatchingNames(
                txmaAuditQueue, List.of(AUTH_TOKEN_SENT_TO_ORCHESTRATION));
    }

    @Test
    void validAuthCodeShouldSucceedTheFirstTimeItIsUsedButShouldNotBePossibleToUseTwice()
            throws JOSEException {
        Map<String, List<String>> baseParams =
                baseTokenRequestParamsWithoutClientAssertion(VALID_AUTH_CODE);
        Map<String, List<String>> privateKeyJWT = privateKeyJWTParams(EC_KEY_PAIR);
        baseParams.putAll(privateKeyJWT);
        var requestBody = URLUtils.serializeParameters(baseParams);

        var responseOne =
                makeRequest(
                        Optional.of(requestBody),
                        Map.of("Content-Type", "application/x-www-form-urlencoded"),
                        new HashMap<>());

        assertThat(responseOne, hasStatus(200));

        var responseTwo =
                makeRequest(
                        Optional.of(requestBody),
                        Map.of("Content-Type", "application/x-www-form-urlencoded"),
                        new HashMap<>());

        assertThat(responseTwo, hasStatus(400));
    }

    @Test
    void shouldReturn400ForAuthCodeThatHasExpired() throws JOSEException {
        Map<String, List<String>> baseParams =
                baseTokenRequestParamsWithoutClientAssertion(INVALID_AUTH_CODE);
        Map<String, List<String>> privateKeyJWT = privateKeyJWTParams(EC_KEY_PAIR);
        baseParams.putAll(privateKeyJWT);
        var requestBody = URLUtils.serializeParameters(baseParams);

        var response =
                makeRequest(
                        Optional.of(requestBody),
                        Map.of("Content-Type", "application/x-www-form-urlencoded"),
                        new HashMap<>());

        assertThat(response, hasStatus(400));
        assertTrue(
                response.getBody()
                        .contains(
                                "{\"error\":\"invalid_request\",\"error_description\":\"Invalid request\"}"));
    }

    private static Map<String, List<String>> privateKeyJWTParams(ECKey ecKeyPair)
            throws JOSEException {
        var expiryDate = NowHelper.nowPlus(5, ChronoUnit.MINUTES);
        var claimsSet =
                new JWTAuthenticationClaimsSet(
                        new ClientID(ORCH_CLIENT_ID),
                        new Audience(buildURI(AUTH_BACKEND_URI.toString(), "token")));
        claimsSet.getExpirationTime().setTime(expiryDate.getTime());
        var privateKeyJWT =
                new PrivateKeyJWT(
                        claimsSet,
                        JWSAlgorithm.ES256,
                        ecKeyPair.toPrivateKey(),
                        ecKeyPair.getKeyID(),
                        null);
        return privateKeyJWT.toParameters();
    }

    private static Map<String, List<String>> baseTokenRequestParamsWithoutClientAssertion(
            String authCode) {
        Map<String, List<String>> baseParams = new HashMap<>();
        baseParams.put(
                "grant_type", Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()));
        baseParams.put("client_id", Collections.singletonList(ORCH_CLIENT_ID));
        baseParams.put("code", Collections.singletonList(authCode));
        baseParams.put("redirect_uri", Collections.singletonList(ORCH_REDIRECT_URI.toString()));
        return baseParams;
    }

    private static class TestConfigurationService extends IntegrationTestConfigurationService {
        private final boolean useAuthJwks;
        private final Optional<String> orchStubPublicSigningKeyOpt;

        public TestConfigurationService(
                SqsQueueExtension notificationQueue,
                TokenSigningExtension tokenSigningKey,
                TokenSigningExtension docAppPrivateKeyJwtSigner) {
            this(
                    notificationQueue,
                    tokenSigningKey,
                    docAppPrivateKeyJwtSigner,
                    false,
                    Optional.of(STUB_PUBLIC_KEY));
        }

        public TestConfigurationService(
                SqsQueueExtension notificationQueue,
                TokenSigningExtension tokenSigningKey,
                TokenSigningExtension docAppPrivateKeyJwtSigner,
                boolean useAuthJwks,
                Optional<String> orchStubPublicSigningKeyOpt) {
            super(
                    notificationQueue,
                    tokenSigningKey,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters);
            this.useAuthJwks = useAuthJwks;
            this.orchStubPublicSigningKeyOpt = orchStubPublicSigningKeyOpt;
        }

        @Override
        public String getTxmaAuditQueueUrl() {
            return txmaAuditQueue.getQueueUrl();
        }

        @Override
        public URI getAuthenticationAuthCallbackURI() {
            return ORCH_REDIRECT_URI;
        }

        @Override
        public URI getAuthenticationBackendURI() {
            return AUTH_BACKEND_URI;
        }

        @Override
        public String getOrchestrationClientId() {
            return ORCH_CLIENT_ID;
        }

        @Override
        public URL getAuthJwksUrl() {
            try {
                return authJwksExtension.getJwksUrl();
            } catch (MalformedURLException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public List<String> getOrchestrationToAuthenticationSigningPublicKeys() {
            List<String> keys = new ArrayList<>();
            orchStubPublicSigningKeyOpt.ifPresent(keys::add);
            if (!useAuthJwks) {
                keys.add(EC_PUBLIC_KEY);
            }
            return keys;
        }

        @Override
        public Optional<String> getOrchestrationStubToAuthenticationSigningPublicKey() {
            return orchStubPublicSigningKeyOpt;
        }

        @Override
        public boolean isUseAuthJwksEnabled() {
            return useAuthJwks;
        }
    }
}
