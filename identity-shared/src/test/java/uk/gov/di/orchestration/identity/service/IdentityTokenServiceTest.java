package uk.gov.di.orchestration.identity.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.temporal.ChronoUnit;

import static com.nimbusds.common.contenttype.ContentType.APPLICATION_JSON;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.orchestration.sharedtest.exceptions.Unchecked.unchecked;

public class IdentityTokenServiceTest {

    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final KmsConnectionService kmsService = mock(KmsConnectionService.class);

    private static final URI BACKEND_URI = URI.create("http://identity-backend/");
    private static final URI REDIRECT_URI = URI.create("http://redirect");
    private static final ClientID CLIENT_ID = new ClientID("some-client-id");
    private static final String KEY_ID = "14342354354353";
    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private IdentityTokenService tokenService;
    private ECKey ecPrivateKey;

    @BeforeEach
    void setUp() throws JOSEException {
        var signingJWK =
                new ECKeyGenerator(Curve.P_256)
                        .keyID(KEY_ID)
                        .algorithm(JWSAlgorithm.ES256)
                        .generate();
        ecPrivateKey = signingJWK.toECKey();
        tokenService =
                spy(
                        new IdentityTokenService(
                                kmsService,
                                REDIRECT_URI,
                                BACKEND_URI,
                                CLIENT_ID.getValue(),
                                BACKEND_URI.toString(),
                                signingJWK,
                                KEY_ID));
        when(configService.getAccessTokenExpiry()).thenReturn(300L);
    }

    @Test
    void shouldConstructTokenRequest() throws Exception {
        mockKmsSigningJwt();
        TokenRequest tokenRequest = tokenService.constructTokenRequest(AUTH_CODE.getValue());
        assertThat(tokenRequest.getEndpointURI().toString(), equalTo(BACKEND_URI + "token"));
        assertThat(
                tokenRequest.getClientAuthentication().getMethod().getValue(),
                equalTo("private_key_jwt"));
        assertThat(
                tokenRequest.toHTTPRequest().getBodyAsFormParameters().get("redirect_uri").get(0),
                equalTo(REDIRECT_URI.toString()));
        assertThat(
                tokenRequest.toHTTPRequest().getBodyAsFormParameters().get("grant_type").get(0),
                equalTo(GrantType.AUTHORIZATION_CODE.getValue()));
        assertThat(
                tokenRequest.toHTTPRequest().getBodyAsFormParameters().get("client_id").get(0),
                equalTo(CLIENT_ID.getValue()));
        assertThat(
                tokenRequest.toHTTPRequest().getBodyAsFormParameters().get("resource"),
                equalTo(null));
        assertSignRequestHeaderEquals(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(KEY_ID).build());
    }

    @Nested
    class SendTokenRequest {
        private final HTTPRequest httpRequest = mock(HTTPRequest.class);
        private final TokenRequest tokenRequest = mock(TokenRequest.class);

        @Test
        void shouldCallTokenEndpointAndReturn200() throws IOException {
            when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);
            when(tokenRequest.toHTTPRequest().send()).thenReturn(getSuccessfulTokenHttpResponse());

            var tokenResponse = tokenService.sendTokenRequest(tokenRequest);

            assertThat(tokenResponse.indicatesSuccess(), equalTo(true));
        }

        @Test
        void shouldRetryTokenEndpointOnceAndParseSuccessfulSecondResponse() throws Exception {
            mockKmsSigningJwt();
            when(tokenService.constructTokenRequest(AUTH_CODE.getValue())).thenReturn(tokenRequest);
            when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);
            when(tokenRequest.toHTTPRequest().send())
                    .thenReturn(new HTTPResponse(500))
                    .thenReturn(getSuccessfulTokenHttpResponse());

            var tokenResponse = tokenService.getToken(AUTH_CODE.getValue());

            assertThat(tokenResponse.indicatesSuccess(), equalTo(true));
            verify(tokenService, times(2)).constructTokenRequest(AUTH_CODE.getValue());
        }

        @Test
        void shouldReturnUnsuccessfulResponseIfTwoCallsToTokenEndpointFail() throws Exception {
            mockKmsSigningJwt();
            when(tokenService.constructTokenRequest(AUTH_CODE.getValue())).thenReturn(tokenRequest);
            when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);
            when(tokenRequest.toHTTPRequest().send()).thenReturn(new HTTPResponse(500));

            var tokenResponse = tokenService.getToken(AUTH_CODE.getValue());

            assertThat(tokenResponse.indicatesSuccess(), equalTo(false));
            verify(tokenService, times(2)).constructTokenRequest(AUTH_CODE.getValue());
            verify(tokenRequest.toHTTPRequest(), times(2)).send();
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
            tokenHTTPResponse.setBody(tokenResponseContent);

            return tokenHTTPResponse;
        }
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
        var claimsSet =
                new JWTAuthenticationClaimsSet(
                        new ClientID(CLIENT_ID),
                        singletonList(new Audience(buildURI(BACKEND_URI.toString(), "token"))),
                        NowHelper.nowPlus(5, ChronoUnit.MINUTES),
                        null,
                        NowHelper.now(),
                        new JWTID());
        var ecdsaSigner = new ECDSASigner(ecPrivateKey);
        var jwsHeader =
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(ecPrivateKey.getKeyID()).build();
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
}
