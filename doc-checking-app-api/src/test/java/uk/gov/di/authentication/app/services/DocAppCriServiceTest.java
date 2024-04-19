package uk.gov.di.authentication.app.services;

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
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.JWTID;
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
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;

import java.io.IOException;
import java.net.URI;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.time.temporal.ChronoUnit;

import static com.nimbusds.common.contenttype.ContentType.APPLICATION_JSON;
import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.orchestration.sharedtest.exceptions.Unchecked.unchecked;

class DocAppCriServiceTest {

    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final KmsConnectionService kmsService = mock(KmsConnectionService.class);
    private final HTTPRequest httpRequest = mock(HTTPRequest.class);
    private static final URI CRI_URI = URI.create("http://cri/");
    private static final URI REDIRECT_URI = URI.create("http://redirect");
    private static final ClientID CLIENT_ID = new ClientID("some-client-id");
    private static final String SIGNING_KID = "14342354354353";
    private static final String DOC_APP_SUBJECT_ID = "some-doc-app-subject-id";
    private static final URI DOC_APP_JWKS_URI =
            URI.create("http://localhost/doc-app/.well-known/jwks.json");
    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private DocAppCriService docAppCriService;

    @BeforeEach
    void setUp() {
        docAppCriService = new DocAppCriService(configService, kmsService);
        when(configService.getDocAppBackendURI()).thenReturn(CRI_URI);
        when(configService.getDocAppAuthorisationClientId()).thenReturn(CLIENT_ID.getValue());
        when(configService.getAccessTokenExpiry()).thenReturn(300L);
        when(configService.getDocAppAuthorisationCallbackURI()).thenReturn(REDIRECT_URI);
        when(configService.getEnvironment()).thenReturn("test");
        when(configService.getDocAppJwksUri()).thenReturn(DOC_APP_JWKS_URI);
    }

    @Test
    void shouldConstructTokenRequest() throws JOSEException {
        signJWTWithKMS();
        when(kmsService.getPublicKey(any(GetPublicKeyRequest.class)))
                .thenReturn(GetPublicKeyResponse.builder().keyId("789789789789789").build());
        TokenRequest tokenRequest = docAppCriService.constructTokenRequest(AUTH_CODE.getValue());
        assertThat(tokenRequest.getEndpointURI().toString(), equalTo(CRI_URI + "token"));
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
    void shouldUseNewDocAppAud() throws JOSEException {
        Audience newAudience = new Audience("https://www.review-b.test.account.gov.uk");
        when(configService.isDocAppNewAudClaimEnabled()).thenReturn(true);
        when(configService.getDocAppAudClaim()).thenReturn(newAudience);

        signJWTWithKMS();
        when(kmsService.getPublicKey(any(GetPublicKeyRequest.class)))
                .thenReturn(GetPublicKeyResponse.builder().keyId("789789789789789").build());

        TokenRequest tokenRequest = docAppCriService.constructTokenRequest(AUTH_CODE.getValue());

        var clientAuth = (PrivateKeyJWT) tokenRequest.getClientAuthentication();
        assertThat(clientAuth.getJWTAuthenticationClaimsSet().getAudience(), contains(newAudience));
    }

    @Test
    void shouldCallTokenEndpointAndReturn200() throws IOException {
        var tokenRequest = mock(TokenRequest.class);
        when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);
        when(tokenRequest.toHTTPRequest().send()).thenReturn(getSuccessfulTokenHttpResponse());

        var tokenResponse = docAppCriService.sendTokenRequest(tokenRequest);

        assertThat(tokenResponse.indicatesSuccess(), equalTo(true));
    }

    @Test
    void shouldRetryCallToTokenIfFirstCallFails() throws IOException {
        var tokenRequest = mock(TokenRequest.class);
        when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);

        when(tokenRequest.toHTTPRequest().send())
                .thenReturn(new HTTPResponse(500))
                .thenReturn(getSuccessfulTokenHttpResponse());

        var tokenResponse = docAppCriService.sendTokenRequest(tokenRequest);

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

        var tokenResponse = docAppCriService.sendTokenRequest(tokenRequest);

        assertThat(tokenResponse.indicatesSuccess(), equalTo(false));
        verify(tokenRequest.toHTTPRequest(), times(2)).send();
    }

    @Test
    void shouldCallUserInfoEndpointAndReturn200()
            throws IOException,
                    JOSEException,
                    NoSuchAlgorithmException,
                    UnsuccessfulCredentialResponseException {
        var signedJwtOne = generateSignedJWT(new JWTClaimsSet.Builder().build());
        var signedJwtTwo = generateSignedJWT(new JWTClaimsSet.Builder().build());

        var userInfoHTTPResponseContent =
                format(
                        "{"
                                + " \"sub\": \"%s\","
                                + " \"https://vocab.account.gov.uk/v1/credentialJWT\": ["
                                + "     \"%s\","
                                + "     \"%s\""
                                + "]"
                                + "}",
                        DOC_APP_SUBJECT_ID, signedJwtOne.serialize(), signedJwtTwo.serialize());

        var userInfoHTTPResponse = new HTTPResponse(200);
        userInfoHTTPResponse.setEntityContentType(APPLICATION_JSON);
        userInfoHTTPResponse.setContent(userInfoHTTPResponseContent);
        when(httpRequest.send()).thenReturn(userInfoHTTPResponse);

        var response = docAppCriService.sendCriDataRequest(httpRequest, DOC_APP_SUBJECT_ID);

        assertThat(response.size(), equalTo(2));
        assertTrue(response.contains(signedJwtOne.serialize()));
        assertTrue(response.contains(signedJwtTwo.serialize()));
    }

    @Test
    void shouldRetryCallToUserInfoAndReturn200IfFirstCallFails()
            throws NoSuchAlgorithmException,
                    JOSEException,
                    IOException,
                    UnsuccessfulCredentialResponseException {
        var signedJwtOne = generateSignedJWT(new JWTClaimsSet.Builder().build());
        var signedJwtTwo = generateSignedJWT(new JWTClaimsSet.Builder().build());

        var userInfoHTTPResponseContent =
                format(
                        "{"
                                + " \"sub\": \"%s\","
                                + " \"https://vocab.account.gov.uk/v1/credentialJWT\": ["
                                + "     \"%s\","
                                + "     \"%s\""
                                + "]"
                                + "}",
                        DOC_APP_SUBJECT_ID, signedJwtOne.serialize(), signedJwtTwo.serialize());

        var userInfoHTTPResponse = new HTTPResponse(200);
        userInfoHTTPResponse.setEntityContentType(APPLICATION_JSON);
        userInfoHTTPResponse.setContent(userInfoHTTPResponseContent);
        when(httpRequest.send()).thenReturn(new HTTPResponse(500)).thenReturn(userInfoHTTPResponse);

        var response = docAppCriService.sendCriDataRequest(httpRequest, DOC_APP_SUBJECT_ID);

        assertThat(response.size(), equalTo(2));
        assertTrue(response.contains(signedJwtOne.serialize()));
        assertTrue(response.contains(signedJwtTwo.serialize()));
        verify(httpRequest, times(2)).send();
    }

    @Test
    void shouldThrowWhenClientSessionAndUserInfoEndpointDocAppIdDoesNotMatch()
            throws IOException, JOSEException, NoSuchAlgorithmException {
        var signedJwtOne = generateSignedJWT(new JWTClaimsSet.Builder().build());
        var signedJwtTwo = generateSignedJWT(new JWTClaimsSet.Builder().build());

        var userInfoHTTPResponseContent =
                format(
                        "{"
                                + " \"sub\": \"%s\","
                                + " \"https://vocab.account.gov.uk/v1/credentialJWT\": ["
                                + "     \"%s\","
                                + "     \"%s\""
                                + "]"
                                + "}",
                        DOC_APP_SUBJECT_ID, signedJwtOne.serialize(), signedJwtTwo.serialize());

        var userInfoHTTPResponse = new HTTPResponse(200);
        userInfoHTTPResponse.setEntityContentType(APPLICATION_JSON);
        userInfoHTTPResponse.setContent(userInfoHTTPResponseContent);
        when(httpRequest.send()).thenReturn(userInfoHTTPResponse);

        UnsuccessfulCredentialResponseException thrown =
                assertThrows(
                        UnsuccessfulCredentialResponseException.class,
                        () -> docAppCriService.sendCriDataRequest(httpRequest, "different-id"));

        assertEquals(
                "Sub in CRI response does not match docAppSubjectId in client session",
                thrown.getMessage());
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
                        singletonList(new Audience(buildURI(CRI_URI.toString(), "token"))),
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

    public static SignedJWT generateSignedJWT(JWTClaimsSet jwtClaimsSet)
            throws JOSEException, NoSuchAlgorithmException {
        var jwsHeader = new JWSHeader(JWSAlgorithm.ES256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);

        var keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256);
        var keyPair = keyPairGenerator.generateKeyPair();
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
        tokenHTTPResponse.setContent(tokenResponseContent);

        return tokenHTTPResponse;
    }
}
