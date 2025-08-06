package uk.gov.di.authentication.frontendapi.services;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.http.Fault;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulReverificationResponseException;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.io.IOException;
import java.net.URI;
import java.time.temporal.ChronoUnit;
import java.util.stream.Stream;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.stubbing.Scenario.STARTED;
import static com.nimbusds.common.contenttype.ContentType.APPLICATION_JSON;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.shared.helpers.HashHelper.hashSha256String;
import static uk.gov.di.authentication.sharedtest.exceptions.Unchecked.unchecked;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class ReverificationResultServiceTest {
    public static final String TOKEN_REQUEST_ERROR_RESPONSE =
            """
        {
            "error": "server_error",
            "error_description": "server_error_description"
        }
        """;
    public static final String CORRUPT_ERROR_RESPONSE =
            """
        {
            "error": "server_error",
            "error_desc}
        """;
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final KmsConnectionService kmsService = mock(KmsConnectionService.class);
    private final UserInfoRequest userInfoRequest = mock(UserInfoRequest.class);
    private final HTTPRequest httpRequest = mock(HTTPRequest.class);

    private static final URI REDIRECT_URI = URI.create("http://redirect");
    private static final ClientID CLIENT_ID = new ClientID("some-client-id");
    private static final String KEY_ID = "14342354354353";
    private static final String SUCCESSFUL_USER_INFO_HTTP_RESPONSE_CONTENT =
            """
            {
                "sub": "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
                "success": true"
            }
            """;
    public static final String SUCCESSFUL_TOKEN_RESPONSE =
            """
            {
                "access_token": "access-token",
                "token_type": "bearer",
                "expires_in": 3600,
                "scope": "openid"
            }
            """;

    private ReverificationResultService reverificationResultService;

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(ReverificationResultService.class);

    private static URI ipvUri;
    private static WireMockServer wireMockServer;

    @BeforeAll
    static void setUpWireMock() {
        wireMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());
        wireMockServer.start();
        configureFor("localhost", wireMockServer.port());
        ipvUri = URI.create("http://localhost:" + wireMockServer.port());
    }

    @AfterAll
    static void afterAll() {
        wireMockServer.stop();
    }

    @BeforeEach
    void beforeEach() {
        reverificationResultService = new ReverificationResultService(configService, kmsService);

        when(configService.getIPVBackendURI()).thenReturn(URI.create(ipvUri.toString()));

        when(configService.getIPVAuthorisationClientId()).thenReturn(CLIENT_ID.getValue());
        when(configService.getAccessTokenExpiry()).thenReturn(300L);
        when(configService.getIPVAuthorisationCallbackURI()).thenReturn(REDIRECT_URI);
        when(configService.getIPVAudience()).thenReturn(ipvUri.toString());
        when(configService.getMfaResetJarSigningKeyId()).thenReturn(KEY_ID);
        when(configService.getMfaResetJarSigningKeyAlias()).thenReturn(KEY_ID);
    }

    @AfterEach
    void afterEach() {
        wireMockServer.resetAll();
    }

    @Nested
    @DisplayName("Tests for the sendTokenRequest method.")
    class TokenRequestTests {

        @Test
        void shouldCallTokenEndpointAndReturn200() throws JOSEException {
            signJWTWithKMS();

            stubFor(
                    post(urlPathMatching("/token"))
                            .willReturn(
                                    aResponse()
                                            .withStatus(200)
                                            .withHeader("Content-Type", "application/json")
                                            .withBody(SUCCESSFUL_TOKEN_RESPONSE)));

            var tokenResponse = reverificationResultService.getToken("an auth code");

            assertThat(tokenResponse.indicatesSuccess(), equalTo(true));

            var expectedHashedKid = hashSha256String(KEY_ID);

            ArgumentCaptor<SignRequest> signRequestCaptor =
                    ArgumentCaptor.forClass(SignRequest.class);
            verify(kmsService, times(1)).getPublicKey(any(GetPublicKeyRequest.class));
            verify(kmsService, times(1)).sign(signRequestCaptor.capture());

            SignRequest actualSignRequest = signRequestCaptor.getValue();
            assertThat(actualSignRequest.keyId(), equalTo(KEY_ID));
            assertThat(
                    actualSignRequest.signingAlgorithm(),
                    equalTo(SigningAlgorithmSpec.ECDSA_SHA_256));

            String jwtMessage = actualSignRequest.message().asUtf8String();
            String[] parts = jwtMessage.split("\\.");
            String decodedHeader = new String(Base64URL.from(parts[0]).decode());
            assertThat(
                    decodedHeader,
                    org.hamcrest.Matchers.containsString("\"kid\":\"" + expectedHashedKid + "\""));
        }

        @Test
        void shouldRetryTokenEndpointOnceAndParseSuccessFulSecondResponse() throws JOSEException {
            signJWTWithKMS();

            stubFor(
                    post(urlPathMatching("/token"))
                            .inScenario("temp fail")
                            .whenScenarioStateIs(STARTED)
                            .willReturn(aResponse().withStatus(500))
                            .willSetStateTo("success call"));

            stubFor(
                    post(urlPathMatching("/token"))
                            .inScenario("temp fail")
                            .whenScenarioStateIs("success call")
                            .willReturn(
                                    aResponse()
                                            .withStatus(200)
                                            .withHeader("Content-Type", "application/json")
                                            .withBody(SUCCESSFUL_TOKEN_RESPONSE)));

            var tokenResponse = reverificationResultService.getToken("an auth code");

            assertThat(tokenResponse.indicatesSuccess(), equalTo(true));
        }

        static Stream<Arguments> errorResponseArgumentProvider() {
            return Stream.of(
                    Arguments.of(
                            "Well formatted error response",
                            """
                        {
                            "error": "server_error",
                            "error_description": "server_error_description"
                        }
                        """
                                    .strip()
                                    .replace("\n", "")),
                    Arguments.of(
                            "Not a JSON error response",
                            """
                        {
                            "error": "server_error,
                            "error_description": "server_error_description"
                        }
                        """
                                    .strip()
                                    .replace("\n", "")),
                    Arguments.of("Empty error response", ""),
                    Arguments.of(
                            "Unexpected JSON error response",
                            """
                        {   "unknown": "unexpected",
                            "error": "server_error,
                            "error_description": "server_error_description"
                        }
                        """
                                    .strip()
                                    .replace("\n", "")));
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("errorResponseArgumentProvider")
        void shouldRetryTokenEndpointIfErrorResponse(String scenario, String error)
                throws JOSEException {

            signJWTWithKMS();

            stubFor(
                    post(urlPathMatching("/token"))
                            .inScenario("temp fail")
                            .whenScenarioStateIs(STARTED)
                            .willReturn(aResponse().withStatus(500).withBody(error))
                            .willSetStateTo("success call"));

            stubFor(
                    post(urlPathMatching("/token"))
                            .inScenario("temp fail")
                            .whenScenarioStateIs("success call")
                            .willReturn(
                                    aResponse()
                                            .withStatus(200)
                                            .withHeader("Content-Type", "application/json")
                                            .withBody(SUCCESSFUL_TOKEN_RESPONSE)));

            var tokenResponse = reverificationResultService.getToken("an auth code");

            assertThat(tokenResponse.indicatesSuccess(), equalTo(true));

            var template =
                    "Unsuccessful {} response from IPV token endpoint on attempt: {}; error: {}";
            template = template.replaceFirst("\\{}", "500");
            template = template.replaceFirst("\\{}", "1");
            template = template.replaceFirst("\\{}", error);

            assertThat(logging.events(), hasItem(withMessageContaining(template)));
        }

        @Test
        void shouldReturnUnsuccessfulResponseIfTwoCallsToIPVTokenEndpointFail()
                throws JOSEException {
            signJWTWithKMS();

            stubFor(
                    post(urlPathMatching("/token"))
                            .willReturn(
                                    aResponse()
                                            .withStatus(500)
                                            .withBody(TOKEN_REQUEST_ERROR_RESPONSE)));

            var tokenResponse = reverificationResultService.getToken("an auth code");

            assertThat(tokenResponse.indicatesSuccess(), equalTo(false));
            WireMock.verify(2, postRequestedFor(urlPathMatching("/token")));
        }

        @Test
        void shouldThrowRTEWhenSendToIPVFails() throws JOSEException {
            signJWTWithKMS();

            stubFor(
                    post(urlPathMatching("/token"))
                            .willReturn(aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));

            var tokenResponse = reverificationResultService.getToken("an auth code");

            assertThat(tokenResponse.indicatesSuccess(), equalTo(false));
        }

        @Test
        void shouldThrowRTEWhenTokenParsingFails() throws JOSEException {
            signJWTWithKMS();

            stubFor(
                    post(urlPathMatching("/token"))
                            .willReturn(
                                    aResponse().withStatus(500).withBody(CORRUPT_ERROR_RESPONSE)));

            var tokenResponse = reverificationResultService.getToken("an auth code");

            assertThat(tokenResponse.indicatesSuccess(), equalTo(false));
        }
    }

    @Nested
    @DisplayName("Tests for the sendIpvReverificationRequest method.")
    class ReverificationRequestTests {

        @Test
        void shouldCallIPVReverificationRequest()
                throws IOException, UnsuccessfulReverificationResponseException {
            var userInfoHTTPResponse = new HTTPResponse(200);
            userInfoHTTPResponse.setEntityContentType(APPLICATION_JSON);
            userInfoHTTPResponse.setContent(SUCCESSFUL_USER_INFO_HTTP_RESPONSE_CONTENT);
            when(httpRequest.send()).thenReturn(userInfoHTTPResponse);
            when(userInfoRequest.toHTTPRequest()).thenReturn(httpRequest);

            var reverificationResult =
                    reverificationResultService.sendIpvReverificationRequest(userInfoRequest);
            assertThat(
                    reverificationResult.getContent(), equalTo(userInfoHTTPResponse.getContent()));
        }

        @Test
        void shouldRetryCallToIPVUserIdentity()
                throws IOException, UnsuccessfulReverificationResponseException {
            var userInfoHTTPResponse = new HTTPResponse(200);
            userInfoHTTPResponse.setEntityContentType(APPLICATION_JSON);
            userInfoHTTPResponse.setContent(SUCCESSFUL_USER_INFO_HTTP_RESPONSE_CONTENT);
            when(userInfoRequest.toHTTPRequest()).thenReturn(httpRequest);

            when(httpRequest.send())
                    .thenReturn(new HTTPResponse(500))
                    .thenReturn(userInfoHTTPResponse);

            var reverificationResult =
                    reverificationResultService.sendIpvReverificationRequest(userInfoRequest);
            assertThat(
                    reverificationResult.getContent(), equalTo(userInfoHTTPResponse.getContent()));
        }

        @Test
        void shouldReturnUnsuccessfulResponseIfTwoCallsToIPVUserIdentityFail() throws IOException {
            var userInfoHTTPResponse = new HTTPResponse(200);
            userInfoHTTPResponse.setEntityContentType(APPLICATION_JSON);
            userInfoHTTPResponse.setContent(SUCCESSFUL_USER_INFO_HTTP_RESPONSE_CONTENT);
            when(userInfoRequest.toHTTPRequest()).thenReturn(httpRequest);

            when(httpRequest.send()).thenReturn(new HTTPResponse(500));

            assertThrows(
                    UnsuccessfulReverificationResponseException.class,
                    () ->
                            reverificationResultService.sendIpvReverificationRequest(
                                    userInfoRequest));

            verify(userInfoRequest.toHTTPRequest(), times(2)).send();
        }
    }

    private void signJWTWithKMS() throws JOSEException {
        var ecSigningKey =
                new ECKeyGenerator(Curve.P_256)
                        .keyID(KEY_ID)
                        .algorithm(JWSAlgorithm.ES256)
                        .generate();
        var claimsSet =
                new JWTAuthenticationClaimsSet(
                        new ClientID(CLIENT_ID),
                        singletonList(new Audience(buildURI(ipvUri.toString(), "/token"))),
                        NowHelper.nowPlus(5, ChronoUnit.MINUTES),
                        null,
                        NowHelper.now(),
                        new JWTID());
        var ecdsaSigner = new ECDSASigner(ecSigningKey);
        var jwsHeader =
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(ecSigningKey.getKeyID()).build();
        var signedJWT = new SignedJWT(jwsHeader, claimsSet.toJWTClaimsSet());
        unchecked(signedJWT::sign).accept(ecdsaSigner);
        byte[] idTokenSignatureDer =
                ECDSA.transcodeSignatureToDER(signedJWT.getSignature().decode());
        var signResult =
                SignResponse.builder()
                        .signature(SdkBytes.fromByteArray(idTokenSignatureDer))
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .keyId(KEY_ID)
                        .build();

        when(kmsService.getPublicKey(any(GetPublicKeyRequest.class)))
                .thenReturn(GetPublicKeyResponse.builder().keyId(KEY_ID).build());
        when(kmsService.sign(any(SignRequest.class))).thenReturn(signResult);
    }
}
