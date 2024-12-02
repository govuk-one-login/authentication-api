package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulReverificationResponseException;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.io.IOException;
import java.net.URI;
import java.time.temporal.ChronoUnit;

import static com.nimbusds.common.contenttype.ContentType.APPLICATION_JSON;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.sharedtest.exceptions.Unchecked.unchecked;

class ReverificationResultServiceTest {

    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final KmsConnectionService kmsService = mock(KmsConnectionService.class);
    private final UserInfoRequest userInfoRequest = mock(UserInfoRequest.class);
    private final HTTPRequest httpRequest = mock(HTTPRequest.class);
    private final TokenRequest tokenRequest = mock(TokenRequest.class);

    private static final URI IPV_URI = URI.create("http://ipv/");
    private static final URI REDIRECT_URI = URI.create("http://redirect");
    private static final ClientID CLIENT_ID = new ClientID("some-client-id");
    private static final String KEY_ID = "14342354354353";
    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private static final String SUCCESSFUL_USER_INFO_HTTP_RESPONSE_CONTENT =
            "{"
                    + " \"sub\": \"urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6\","
                    + "\"success\": true"
                    + "}";
    private ReverificationResultService reverificationResultService;

    @BeforeEach
    void setUp() {
        reverificationResultService = new ReverificationResultService(configService, kmsService);
        when(configService.getIPVBackendURI()).thenReturn(IPV_URI);
        when(configService.getIPVAuthorisationClientId()).thenReturn(CLIENT_ID.getValue());
        when(configService.getAccessTokenExpiry()).thenReturn(300L);
        when(configService.getIPVAuthorisationCallbackURI()).thenReturn(REDIRECT_URI);
        when(configService.getIPVAudience()).thenReturn(IPV_URI.toString());
    }

    @Test
    void shouldConstructTokenRequest() throws JOSEException {
        signJWTWithKMS();
        TokenRequest newTokenRequest =
                reverificationResultService.constructTokenRequest(AUTH_CODE.getValue());
        assertThat(newTokenRequest.getEndpointURI().toString(), equalTo(IPV_URI + "token"));
        assertThat(
                newTokenRequest.getClientAuthentication().getMethod().getValue(),
                equalTo("private_key_jwt"));
        assertThat(
                newTokenRequest.toHTTPRequest().getQueryParameters().get("redirect_uri").get(0),
                equalTo(REDIRECT_URI.toString()));
        assertThat(
                newTokenRequest.toHTTPRequest().getQueryParameters().get("grant_type").get(0),
                equalTo(GrantType.AUTHORIZATION_CODE.getValue()));
        assertThat(
                newTokenRequest.toHTTPRequest().getQueryParameters().get("client_id").get(0),
                equalTo(CLIENT_ID.getValue()));
    }

    @Test
    void shouldCallTokenEndpointAndReturn200() throws IOException {
        when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);
        when(tokenRequest.toHTTPRequest().send()).thenReturn(getSuccessfulTokenHttpResponse());

        var tokenResponse = reverificationResultService.sendTokenRequest(tokenRequest);

        assertThat(tokenResponse.indicatesSuccess(), equalTo(true));
    }

    @Test
    void shouldRetryTokenEndpointOnceAndParseSuccessFulSecondResponse() throws IOException {
        when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);
        when(tokenRequest.toHTTPRequest().send())
                .thenReturn(new HTTPResponse(500))
                .thenReturn(getSuccessfulTokenHttpResponse());

        var tokenResponse = reverificationResultService.sendTokenRequest(tokenRequest);

        assertThat(tokenResponse.indicatesSuccess(), equalTo(true));
    }

    @Test
    void shouldReturnUnsuccessfulResponseIfTwoCallsToIPVTokenEndpointFail() throws IOException {
        when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);
        when(tokenRequest.toHTTPRequest().send()).thenReturn(new HTTPResponse(500));

        var tokenResponse = reverificationResultService.sendTokenRequest(tokenRequest);

        assertThat(tokenResponse.indicatesSuccess(), equalTo(false));
        verify(tokenRequest.toHTTPRequest(), times(2)).send();
    }

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
        assertThat(reverificationResult.getContent(), equalTo(userInfoHTTPResponse.getContent()));
    }

    @Test
    void shouldRetryCallToIPVUserIdentity()
            throws IOException, UnsuccessfulReverificationResponseException {
        var userInfoHTTPResponse = new HTTPResponse(200);
        userInfoHTTPResponse.setEntityContentType(APPLICATION_JSON);
        userInfoHTTPResponse.setContent(SUCCESSFUL_USER_INFO_HTTP_RESPONSE_CONTENT);
        when(userInfoRequest.toHTTPRequest()).thenReturn(httpRequest);

        when(httpRequest.send()).thenReturn(new HTTPResponse(500)).thenReturn(userInfoHTTPResponse);

        var reverificationResult =
                reverificationResultService.sendIpvReverificationRequest(userInfoRequest);
        assertThat(reverificationResult.getContent(), equalTo(userInfoHTTPResponse.getContent()));
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
                () -> {
                    reverificationResultService.sendIpvReverificationRequest(userInfoRequest);
                });

        verify(userInfoRequest.toHTTPRequest(), times(2)).send();
    }

    @Test
    void shouldThrowRTEWhenSendToIPVFails() throws IOException {
        when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);
        when(tokenRequest.toHTTPRequest().send()).thenThrow(new IOException());

        assertThrows(
                RuntimeException.class,
                () -> {
                    reverificationResultService.sendTokenRequest(tokenRequest);
                });
    }

    @Test
    void shouldThrowRTEWhenTokenParsingFails() throws IOException {
        when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);

        HTTPResponse badResponse = new HTTPResponse(200);
        badResponse.setContent("bad json");

        when(tokenRequest.toHTTPRequest().send()).thenReturn(badResponse);

        assertThrows(
                RuntimeException.class,
                () -> {
                    reverificationResultService.sendTokenRequest(tokenRequest);
                });
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
                        singletonList(new Audience(buildURI(IPV_URI.toString(), "token"))),
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

        when(kmsService.sign(any(SignRequest.class))).thenReturn(signResult);
    }

    public HTTPResponse getSuccessfulTokenHttpResponse() {
        var tokenResponseContent =
                "{"
                        + "  \"access_token\": \"740e5834-3a29-46b4-9a6f-16142fde533a\","
                        + "  \"token_type\": \"bearer\","
                        + "  \"expires_in\": \"3600\""
                        + "}";
        var tokenHTTPResponse = new HTTPResponse(200);
        tokenHTTPResponse.setEntityContentType(APPLICATION_JSON);
        tokenHTTPResponse.setContent(tokenResponseContent);

        return tokenHTTPResponse;
    }
}
