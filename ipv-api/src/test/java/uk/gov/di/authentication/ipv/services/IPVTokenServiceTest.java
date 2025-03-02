package uk.gov.di.authentication.ipv.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
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
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.orchestration.shared.entity.IdentityClaims;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.JwksService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;

import static com.nimbusds.common.contenttype.ContentType.APPLICATION_JSON;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.entity.IdentityClaims.VOT;
import static uk.gov.di.orchestration.shared.entity.IdentityClaims.VTM;
import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.orchestration.sharedtest.exceptions.Unchecked.unchecked;

class IPVTokenServiceTest {

    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final KmsConnectionService kmsService = mock(KmsConnectionService.class);
    private final JwksService jwksService = mock(JwksService.class);
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
                    + " \"vot\": \"P2\","
                    + " \"vtm\": \"<trust mark>\","
                    + " \"https://vocab.account.gov.uk/v1/credentialJWT\": ["
                    + "     \"<JWT-encoded VC 1>\","
                    + "     \"<JWT-encoded VC 2>\""
                    + "],"
                    + " \"https://vocab.account.gov.uk/v1/coreIdentity\": {"
                    + "     \"name\": ["
                    + "         { } "
                    + "     ],"
                    + "     \"birthDate\": [ "
                    + "         { } "
                    + "     ]"
                    + " }"
                    + "}";
    private IPVTokenService ipvTokenService;

    @BeforeEach
    void setUp() throws JOSEException {
        ipvTokenService = new IPVTokenService(configService, kmsService, jwksService);
        when(configService.getIPVBackendURI()).thenReturn(IPV_URI);
        when(configService.getIPVAuthorisationClientId()).thenReturn(CLIENT_ID.getValue());
        when(configService.getAccessTokenExpiry()).thenReturn(300L);
        when(configService.getIPVAuthorisationCallbackURI()).thenReturn(REDIRECT_URI);
        when(configService.getIPVAudience()).thenReturn(IPV_URI.toString());
        when(configService.getIPVTokenSigningKeyAlias()).thenReturn(KEY_ID);
        when(jwksService.getPublicIpvTokenJwkWithOpaqueId())
                .thenReturn(
                        new ECKeyGenerator(Curve.P_256)
                                .keyID(KEY_ID)
                                .algorithm(JWSAlgorithm.ES256)
                                .generate());
    }

    @Test
    void shouldConstructTokenRequest() throws JOSEException, ParseException {
        mockKmsSigningJwt();
        TokenRequest tokenRequest = ipvTokenService.constructTokenRequest(AUTH_CODE.getValue());
        assertThat(tokenRequest.getEndpointURI().toString(), equalTo(IPV_URI + "token"));
        assertThat(
                tokenRequest.getClientAuthentication().getMethod().getValue(),
                equalTo("private_key_jwt"));
        assertThat(
                tokenRequest.toHTTPRequest().getQueryParameters().get("redirect_uri").get(0),
                equalTo(REDIRECT_URI.toString()));
        assertThat(
                tokenRequest.toHTTPRequest().getQueryParameters().get("grant_type").get(0),
                equalTo(GrantType.AUTHORIZATION_CODE.getValue()));
        assertThat(
                tokenRequest.toHTTPRequest().getQueryParameters().get("client_id").get(0),
                equalTo(CLIENT_ID.getValue()));
        assertThat(
                tokenRequest.toHTTPRequest().getQueryParameters().get("resource"), equalTo(null));
        assertSignRequestHeaderEquals(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(KEY_ID).build());
    }

    @Test
    void shouldCallTokenEndpointAndReturn200() throws IOException {
        when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);
        when(tokenRequest.toHTTPRequest().send()).thenReturn(getSuccessfulTokenHttpResponse());

        var tokenResponse = ipvTokenService.sendTokenRequest(tokenRequest);

        assertThat(tokenResponse.indicatesSuccess(), equalTo(true));
    }

    @Test
    void shouldRetryTokenEndpointOnceAndParseSuccessFulSecondResponse() throws IOException {
        when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);
        when(tokenRequest.toHTTPRequest().send())
                .thenReturn(new HTTPResponse(500))
                .thenReturn(getSuccessfulTokenHttpResponse());

        var tokenResponse = ipvTokenService.sendTokenRequest(tokenRequest);

        assertThat(tokenResponse.indicatesSuccess(), equalTo(true));
    }

    @Test
    void shouldReturnUnsuccessfulResponseIfTwoCallsToIPVTokenEndpointFail() throws IOException {
        when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);
        when(tokenRequest.toHTTPRequest().send()).thenReturn(new HTTPResponse(500));

        var tokenResponse = ipvTokenService.sendTokenRequest(tokenRequest);

        assertThat(tokenResponse.indicatesSuccess(), equalTo(false));
        verify(tokenRequest.toHTTPRequest(), times(2)).send();
    }

    @Test
    void shouldCallIPVUserIdentityRequestAndParseCorrectly()
            throws IOException, UnsuccessfulCredentialResponseException {
        var userInfoHTTPResponse = new HTTPResponse(200);
        userInfoHTTPResponse.setEntityContentType(APPLICATION_JSON);
        userInfoHTTPResponse.setContent(SUCCESSFUL_USER_INFO_HTTP_RESPONSE_CONTENT);
        when(httpRequest.send()).thenReturn(userInfoHTTPResponse);
        when(userInfoRequest.toHTTPRequest()).thenReturn(httpRequest);

        var userIdentityUserInfo = ipvTokenService.sendIpvUserIdentityRequest(userInfoRequest);
        assertThat(
                userIdentityUserInfo.getSubject().getValue(),
                equalTo("urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6"));
        assertThat(userIdentityUserInfo.getClaim(VOT.getValue()), equalTo("P2"));
        assertThat(userIdentityUserInfo.getClaim(VTM.getValue()), equalTo("<trust mark>"));
        assertThat(
                ((ArrayList)
                                userIdentityUserInfo.getClaim(
                                        IdentityClaims.CREDENTIAL_JWT.getValue()))
                        .size(),
                equalTo(2));
        assertThat(
                ((HashMap) userIdentityUserInfo.getClaim(IdentityClaims.CORE_IDENTITY.getValue()))
                        .size(),
                equalTo(2));
        assertTrue(
                ((HashMap) userIdentityUserInfo.getClaim(IdentityClaims.CORE_IDENTITY.getValue()))
                        .containsKey("name"));
        assertTrue(
                ((HashMap) userIdentityUserInfo.getClaim(IdentityClaims.CORE_IDENTITY.getValue()))
                        .containsKey("birthDate"));
    }

    @Test
    void shouldRetryCallToIPVUserIdentityOnceAndParseSuccessFulSecondResponse()
            throws IOException, UnsuccessfulCredentialResponseException {
        var userInfoHTTPResponse = new HTTPResponse(200);
        userInfoHTTPResponse.setEntityContentType(APPLICATION_JSON);
        userInfoHTTPResponse.setContent(SUCCESSFUL_USER_INFO_HTTP_RESPONSE_CONTENT);
        when(userInfoRequest.toHTTPRequest()).thenReturn(httpRequest);

        when(httpRequest.send()).thenReturn(new HTTPResponse(500)).thenReturn(userInfoHTTPResponse);

        var userIdentityUserInfo = ipvTokenService.sendIpvUserIdentityRequest(userInfoRequest);
        assertThat(
                userIdentityUserInfo.getSubject().getValue(),
                equalTo("urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6"));
    }

    @Test
    void shouldReturnUnsuccessfulResponseIfTwoCallsToIPVUserIdentityFail() throws IOException {
        var userInfoHTTPResponse = new HTTPResponse(200);
        userInfoHTTPResponse.setEntityContentType(APPLICATION_JSON);
        userInfoHTTPResponse.setContent(SUCCESSFUL_USER_INFO_HTTP_RESPONSE_CONTENT);
        when(userInfoRequest.toHTTPRequest()).thenReturn(httpRequest);

        when(httpRequest.send()).thenReturn(new HTTPResponse(500));

        assertThrows(
                UnsuccessfulCredentialResponseException.class,
                () -> {
                    ipvTokenService.sendIpvUserIdentityRequest(userInfoRequest);
                });

        verify(userInfoRequest.toHTTPRequest(), times(2)).send();
    }

    private void assertSignRequestHeaderEquals(JWSHeader expectedHeader) throws ParseException {
        var signRequestCaptor = ArgumentCaptor.forClass(SignRequest.class);
        verify(kmsService).sign(signRequestCaptor.capture());
        var request = signRequestCaptor.getValue();
        var message = request.message().asString(StandardCharsets.UTF_8);
        var actualHeaderString = message.split("\\.")[0];
        var actualHeader = JWSHeader.parse(Base64URL.from(actualHeaderString));
        assertThat(actualHeader.toJSONObject(), equalTo(expectedHeader.toJSONObject()));
    }

    private void mockKmsSigningJwt() throws JOSEException {
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
