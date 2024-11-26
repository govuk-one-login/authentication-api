package uk.gov.di.authentication.oidc.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
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
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;

import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.orchestration.sharedtest.exceptions.Unchecked.unchecked;

class AuthenticationTokenServiceTest {
    private ConfigurationService configurationService = mock(ConfigurationService.class);

    private KmsConnectionService kmsService = mock(KmsConnectionService.class);
    private final HTTPRequest httpRequest = mock(HTTPRequest.class);
    private static final String SIGNING_KID = "14342354354353";
    private static final ClientID CLIENT_ID = new ClientID("some-client-id");
    private static final URI AUTH_BACKEND_URI = URI.create("https://auth.backend.uri/");
    private static final URI ORCH_CALLBACK_URI = URI.create("https://orch.callback.uri/");
    private static final GetPublicKeyResponse PUBLIC_KEY_RESPONSE =
            GetPublicKeyResponse.builder().keyId("test").build();
    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private static final UserInfo USER_INFO = new UserInfo(new Subject());

    private AuthenticationTokenService authenticationTokenService;

    @BeforeEach
    void setUp() {
        when(configurationService.getAuthenticationAuthCallbackURI()).thenReturn(ORCH_CALLBACK_URI);
        when(configurationService.getAuthenticationBackendURI()).thenReturn(AUTH_BACKEND_URI);
        when(configurationService.getOrchestrationClientId()).thenReturn(CLIENT_ID.getValue());
        when(configurationService.getOrchestrationToAuthenticationTokenSigningKeyAlias())
                .thenReturn("token-key-alias");

        when(kmsService.getPublicKey(any())).thenReturn(PUBLIC_KEY_RESPONSE);

        authenticationTokenService =
                new AuthenticationTokenService(configurationService, kmsService);
    }

    @Test
    void shouldConstructTokenRequest() throws JOSEException {
        signJWTWithKMS();
        when(kmsService.getPublicKey(any(GetPublicKeyRequest.class)))
                .thenReturn(GetPublicKeyResponse.builder().keyId("789789789789789").build());
        TokenRequest tokenRequest =
                authenticationTokenService.constructTokenRequest(AUTH_CODE.getValue());
        var parameters = URLUtils.parseParameters(tokenRequest.toHTTPRequest().getBody());
        assertThat(tokenRequest.getEndpointURI().toString(), equalTo(AUTH_BACKEND_URI + "token"));
        assertThat(
                tokenRequest.getClientAuthentication().getMethod().getValue(),
                equalTo("private_key_jwt"));
        assertThat(parameters.get("redirect_uri").get(0), equalTo(ORCH_CALLBACK_URI.toString()));
        assertThat(
                parameters.get("grant_type").get(0),
                equalTo(GrantType.AUTHORIZATION_CODE.getValue()));
        assertThat(parameters.get("client_id").get(0), equalTo(CLIENT_ID.getValue()));
    }

    @Test
    void shouldCallTokenEndpointAndReturn200() throws IOException {
        var tokenRequest = mock(TokenRequest.class);
        when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);
        when(tokenRequest.toHTTPRequest().send()).thenReturn(getSuccessfulTokenHttpResponse());

        var tokenResponse = authenticationTokenService.sendTokenRequest(tokenRequest);

        assertThat(tokenResponse.indicatesSuccess(), equalTo(true));
    }

    @Test
    void shouldRetryCallToTokenIfFirstCallFails() throws IOException {
        var tokenRequest = mock(TokenRequest.class);
        when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);

        when(tokenRequest.toHTTPRequest().send())
                .thenReturn(new HTTPResponse(500))
                .thenReturn(getSuccessfulTokenHttpResponse());

        var tokenResponse = authenticationTokenService.sendTokenRequest(tokenRequest);

        assertThat(tokenResponse.indicatesSuccess(), equalTo(true));
        verify(tokenRequest.toHTTPRequest(), times(2)).send();
    }

    @Test
    void shouldReturnUnsuccessfulTokenResponseIf2CallsToTokenFail() throws IOException {
        var tokenRequest = mock(TokenRequest.class);
        when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);

        when(tokenRequest.toHTTPRequest().send())
                .thenReturn(new HTTPResponse(500))
                .thenReturn(new HTTPResponse(500));

        var tokenResponse = authenticationTokenService.sendTokenRequest(tokenRequest);

        assertThat(tokenResponse.indicatesSuccess(), equalTo(false));
        verify(tokenRequest.toHTTPRequest(), times(2)).send();
    }

    @Test
    void shouldSendUserInfoDataRequestSuccessfully()
            throws IOException, UnsuccessfulCredentialResponseException, Json.JsonException {
        String userInfoJson = String.format("{\"sub\":\"%s\"}", USER_INFO.getSubject().getValue());
        HTTPRequest httpRequest = mock(HTTPRequest.class);
        HTTPResponse httpResponse = mock(HTTPResponse.class);
        when(httpRequest.send()).thenReturn(httpResponse);
        when(httpResponse.indicatesSuccess()).thenReturn(true);
        when(httpResponse.getBody()).thenReturn(userInfoJson);

        Map<String, List<String>> headers = new HashMap<>();
        headers.put("Content-Type", Collections.singletonList("application/json"));
        when(httpResponse.getHeaderMap()).thenReturn(headers);

        UserInfo result = authenticationTokenService.sendUserInfoDataRequest(httpRequest);

        assertThat(result.getSubject(), equalTo(USER_INFO.getSubject()));
        verify(httpRequest, times(1)).send();
    }

    @Test
    void shouldRetrySendingUserInfoDataRequestTwiceIfNotSuccessful() throws IOException {
        HTTPRequest httpRequest = mock(HTTPRequest.class);
        HTTPResponse httpResponse = mock(HTTPResponse.class);
        when(httpRequest.send()).thenReturn(httpResponse);
        int failureStatusCode = 503;
        String failureErrorMessage = "Error content";
        when(httpResponse.getStatusCode()).thenReturn(failureStatusCode);
        when(httpResponse.getBody()).thenReturn(failureErrorMessage);

        UnsuccessfulCredentialResponseException exception =
                assertThrows(
                        UnsuccessfulCredentialResponseException.class,
                        () -> {
                            authenticationTokenService.sendUserInfoDataRequest(httpRequest);
                        });

        assertThat(
                exception.getMessage(),
                equalTo(
                        String.format(
                                "Error %s when attempting to call Authentication userinfo endpoint: %s",
                                failureStatusCode, failureErrorMessage)));
        verify(httpRequest, times(2)).send();
    }

    @Test
    void shouldThrowUnsuccessfulCredentialResponseExceptionWhenHttpContentIsNull() {
        HTTPResponse httpResponse = mock(HTTPResponse.class);
        when(httpResponse.getBody()).thenReturn(null);

        UnsuccessfulCredentialResponseException thrown =
                assertThrows(
                        UnsuccessfulCredentialResponseException.class,
                        () -> {
                            authenticationTokenService.parseUserInfoFromResponse(httpResponse);
                        });

        assertThat(thrown.getMessage(), equalTo("No content in HTTP response"));
    }

    @Test
    void shouldThrowUnsuccessfulCredentialResponseExceptionWhenObjectMapperThrowsException() {
        HTTPResponse httpResponse = mock(HTTPResponse.class);
        when(httpResponse.getBody()).thenReturn("{}");

        UnsuccessfulCredentialResponseException thrown =
                assertThrows(
                        UnsuccessfulCredentialResponseException.class,
                        () -> {
                            authenticationTokenService.parseUserInfoFromResponse(httpResponse);
                        });

        assertThat(
                thrown.getMessage(),
                equalTo("Error parsing authentication userinfo response as JSON"));
    }

    private void signJWTWithKMS() throws JOSEException {
        var ecSigningKey =
                new ECKeyGenerator(Curve.P_256)
                        .keyID(SIGNING_KID)
                        .algorithm(JWSAlgorithm.ES256)
                        .generate();
        var claimsSet =
                new JWTAuthenticationClaimsSet(
                        new ClientID(CLIENT_ID),
                        singletonList(new Audience(buildURI(AUTH_BACKEND_URI.toString(), "token"))),
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
                        .keyId(SIGNING_KID)
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .build();

        when(kmsService.sign(any(SignRequest.class))).thenReturn(signResult);
    }

    public static SignedJWT generateSignedJWT(JWTClaimsSet jwtClaimsSet, KeyPair keyPair)
            throws JOSEException {
        var jwsHeader = new JWSHeader(JWSAlgorithm.ES256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        var ecdsaSigner = new ECDSASigner((ECPrivateKey) keyPair.getPrivate());
        signedJWT.sign(ecdsaSigner);
        return signedJWT;
    }

    public HTTPResponse getSuccessfulTokenHttpResponse() {
        var tokenResponseContent =
                "{"
                        + "  \"access_token\": \"740e5834-3a29-46b4-9a6f-16142fde533a\","
                        + "  \"token_type\": \"bearer\","
                        + "  \"expires_in\": \"3600\","
                        + "  \"uri\": \"https://localhost\""
                        + "}";
        var tokenHTTPResponse = new HTTPResponse(200);
        tokenHTTPResponse.setEntityContentType(APPLICATION_JSON);
        tokenHTTPResponse.setBody(tokenResponseContent);

        return tokenHTTPResponse;
    }
}
