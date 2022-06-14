package uk.gov.di.authentication.ipv.services;

import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SignResult;
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
import uk.gov.di.authentication.shared.entity.IdentityClaims;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;

import static com.nimbusds.common.contenttype.ContentType.APPLICATION_JSON;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.IdentityClaims.VOT;
import static uk.gov.di.authentication.shared.entity.IdentityClaims.VTM;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.sharedtest.exceptions.Unchecked.unchecked;

class IPVTokenServiceTest {

    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final KmsConnectionService kmsService = mock(KmsConnectionService.class);
    private final UserInfoRequest userInfoRequest = mock(UserInfoRequest.class);
    private final HTTPRequest userInfoHTTPRequest = mock(HTTPRequest.class);

    private static final URI IPV_URI = URI.create("http://ipv/");
    private static final URI REDIRECT_URI = URI.create("http://redirect");
    private static final ClientID CLIENT_ID = new ClientID("some-client-id");
    private static final String KEY_ID = "14342354354353";
    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private IPVTokenService ipvTokenService;

    @BeforeEach
    void setUp() {
        ipvTokenService = new IPVTokenService(configService, kmsService);
        when(configService.getIPVBackendURI()).thenReturn(IPV_URI);
        when(configService.getIPVAuthorisationClientId()).thenReturn(CLIENT_ID.getValue());
        when(configService.getAccessTokenExpiry()).thenReturn(300L);
        when(configService.getIPVAuthorisationCallbackURI()).thenReturn(REDIRECT_URI);
        when(configService.getIPVAudience()).thenReturn(IPV_URI.toString());
    }

    @Test
    void shouldConstructTokenRequest() throws JOSEException {
        signJWTWithKMS();
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
    }

    @Test
    void shouldCallIPVUserIdentityRequestAndParseCorrectly() throws IOException {
        var userInfoHTTPResponseContent =
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

        var userInfoHTTPResponse = new HTTPResponse(200);
        userInfoHTTPResponse.setEntityContentType(APPLICATION_JSON);
        userInfoHTTPResponse.setContent(userInfoHTTPResponseContent);
        when(userInfoHTTPRequest.send()).thenReturn(userInfoHTTPResponse);
        when(userInfoRequest.toHTTPRequest()).thenReturn(userInfoHTTPRequest);

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
        var signResult = new SignResult();
        byte[] idTokenSignatureDer =
                ECDSA.transcodeSignatureToDER(signedJWT.getSignature().decode());
        signResult.setSignature(ByteBuffer.wrap(idTokenSignatureDer));
        signResult.setKeyId(KEY_ID);
        signResult.setSigningAlgorithm(JWSAlgorithm.ES256.getName());
        when(kmsService.sign(any(SignRequest.class))).thenReturn(signResult);
    }
}
