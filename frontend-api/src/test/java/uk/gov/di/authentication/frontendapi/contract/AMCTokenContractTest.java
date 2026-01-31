package uk.gov.di.authentication.frontendapi.contract;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit.MockServerConfig;
import au.com.dius.pact.consumer.junit5.PactConsumerTest;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.PactSpecVersion;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.AMCScope;
import uk.gov.di.authentication.frontendapi.services.AMCAuthorizationService;
import uk.gov.di.authentication.frontendapi.services.JwtService;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.KeyPairHelper.GENERATE_RSA_KEY_PAIR;

@PactConsumerTest
@MockServerConfig(hostInterface = "localhost", port = "1234")
class AmcTokenContractTest {

    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final JwtService jwtService = mock(JwtService.class);
    private final NowHelper.NowClock nowClock = mock(NowHelper.NowClock.class);
    private final AuthSessionItem authSessionItem = mock(AuthSessionItem.class);

    private AMCAuthorizationService amcAuthorizationService;

    private static final String INTERNAL_PAIRWISE_ID =
            "urn:fdc:gov.uk:2022:xH7hrtJCgdi2NEF7TXcOC6SMz8DohdoLo9hWqQMWPRk";
    private static final String AUTH_ISSUER_CLAIM = "https://signin.account.gov.uk/";
    private static final String AUTH_TO_AUTH_AUDIENCE = "https://api.manage.account.gov.uk";
    private static final String AUTH_TO_AMC_AUDIENCE = "https://amc.account.gov.uk";
    private static final String CLIENT_ID = "test-client-id";
    private static final String SESSION_ID = "test-session-id";
    private static final String REDIRECT_URI = "https://example.com/callback";
    private static final String AMC_CLIENT_ID = "amc-client-id";
    private static final String EMAIL = "test@example.com";
    private static final String JOURNEY_ID = "test-journey-id";
    private static final String PUBLIC_SUBJECT = "test-public-subject";
    private static final String KEY_ALIAS = "test-key-alias";

    private static final String FIXED_JWE_STRING =
            "eyMockJweHeader.eyMockJwePayload.eyMockJweSignature";

    private static final KeyPair TEST_KEY_PAIR = GENERATE_RSA_KEY_PAIR();
    private static final RSAPublicKey TEST_PUBLIC_KEY = (RSAPublicKey) TEST_KEY_PAIR.getPublic();

    private static final Date NOW = Date.from(Instant.parse("2000-01-01T00:00:00.00Z"));
    private static final long SESSION_EXPIRY = 300L;

    @BeforeEach
    void setUp() {
        amcAuthorizationService = new AMCAuthorizationService(configService, nowClock, jwtService);

        when(configService.getAuthIssuerClaim()).thenReturn(AUTH_ISSUER_CLAIM);
        when(configService.getAuthToAMAPIAudience()).thenReturn(AUTH_TO_AUTH_AUDIENCE);
        when(configService.getAuthToAMCAudience()).thenReturn(AUTH_TO_AMC_AUDIENCE);
        when(configService.getSessionExpiry()).thenReturn(SESSION_EXPIRY);
        when(configService.getAMCRedirectURI()).thenReturn(REDIRECT_URI);
        when(configService.getAMCClientId()).thenReturn(AMC_CLIENT_ID);

        when(configService.getAuthToAMCPublicEncryptionKey()).thenReturn(constructTestPublicKey());
        when(configService.getAuthToAccountManagementPrivateSigningKeyAlias())
                .thenReturn(KEY_ALIAS);
        when(configService.getAuthToAMCPrivateSigningKeyAlias()).thenReturn(KEY_ALIAS);

        when(nowClock.now()).thenReturn(NOW);
        when(nowClock.nowPlus(SESSION_EXPIRY, ChronoUnit.SECONDS))
                .thenReturn(Date.from(Instant.parse("2099-01-01T00:00:00.00Z")));

        when(authSessionItem.getClientId()).thenReturn(CLIENT_ID);
        when(authSessionItem.getSessionId()).thenReturn(SESSION_ID);
        when(authSessionItem.getEmailAddress()).thenReturn(EMAIL);

        when(jwtService.signJWT(any(), any()))
                .thenAnswer(
                        inv -> {
                            JWTClaimsSet claims = inv.getArgument(0);
                            SignedJWT signedJWT =
                                    new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
                            signedJWT.sign(new RSASSASigner(TEST_KEY_PAIR.getPrivate()));
                            return signedJWT;
                        });

        when(jwtService.encryptJWT(any(SignedJWT.class), any()))
                .thenAnswer(
                        inv -> {
                            return new MockEncryptedJWT();
                        });
    }

    @Pact(consumer = "FrontendApiConsumer")
    RequestResponsePact validAuthorizeRequest(PactDslWithProvider builder) {
        return builder.given("AMC accepts valid signed and encrypted JWTs")
                .uponReceiving("A request to authorize")
                .path("/authorize")
                .method("GET")
                .matchQuery("request", FIXED_JWE_STRING)
                .matchQuery("response_type", "code")
                .matchQuery("client_id", AMC_CLIENT_ID)
                .willRespondWith()
                .status(302)
                .toPact();
    }

    @Test
    @PactTestFor(
            providerName = "AmcAuthorizationProvider",
            pactMethod = "validAuthorizeRequest",
            pactVersion = PactSpecVersion.V3)
    void shouldRedirectWithValidToken(MockServer mockServer) throws Exception {
        when(configService.getAMCAuthorizeURI())
                .thenReturn(URI.create(mockServer.getUrl() + "/authorize"));

        var result =
                amcAuthorizationService.buildAuthorizationUrl(
                        INTERNAL_PAIRWISE_ID,
                        new AMCScope[] {AMCScope.ACCOUNT_DELETE},
                        authSessionItem,
                        JOURNEY_ID,
                        PUBLIC_SUBJECT);

        String generatedUrl = result.getSuccess();

        HttpClient client =
                HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(generatedUrl)).GET().build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        int statusCode = response.statusCode();

        assertThat(statusCode, equalTo(302));
    }

    private static String constructTestPublicKey() {
        var encodedKey = Base64.getMimeEncoder().encodeToString(TEST_PUBLIC_KEY.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + encodedKey + "\n-----END PUBLIC KEY-----\n";
    }

    public static class MockEncryptedJWT extends EncryptedJWT {
        public MockEncryptedJWT() {
            super(
                    new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM),
                    new JWTClaimsSet.Builder().build());
        }

        @Override
        public String serialize() {
            return FIXED_JWE_STRING;
        }
    }
}
