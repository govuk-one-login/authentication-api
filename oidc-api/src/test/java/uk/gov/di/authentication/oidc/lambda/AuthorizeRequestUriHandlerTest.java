package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.RequestUriPayload;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.helper.KeyPairHelper;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthorizeRequestUriHandlerTest {

    private static final URI REQUEST_URI = URI.create("https://localhost/request_uri");
    private static final String REDIRECT_URI = "https://localhost:8080";
    private final Context context = mock(Context.class);
    private final HttpClient httpClient = mock(HttpClient.class);
    private final HttpResponse httpResponse = mock(HttpResponse.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private KeyPair keyPair;
    private static final String SCOPE = "openid";
    private static final State STATE = new State();
    private static final ClientID CLIENT_ID = new ClientID("test-id");
    private static final String AUDIENCE = "oidc-audience";
    private AuthorizeRequestUriHandler handler;

    @BeforeEach
    void setup() {
        when(configurationService.getOidcApiBaseURL()).thenReturn(Optional.of(AUDIENCE));
        keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
        handler = new AuthorizeRequestUriHandler(httpClient, configurationService);
    }

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(AuthorizeRequestUriHandler.class);

    @Test
    void shouldSuccessfullyProcessRequestUriPayload()
            throws IOException, InterruptedException, JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .issuer(CLIENT_ID.getValue())
                        .build();
        setupJwtRequest(jwtClaimsSet);
        var event = new RequestUriPayload(generateClientRegistry(), generateAuthRequest());
        var response = handler.handleRequest(event, context);

        assertTrue(response.isSuccessfulRequest());
        assertNull(response.getErrorObject());
    }

    @Test
    void shouldThrowWhenRedirectUriIsInvalid()
            throws IOException, InterruptedException, JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", "https://invalid-redirect-uri")
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .issuer(CLIENT_ID.getValue())
                        .build();
        setupJwtRequest(jwtClaimsSet);
        var event = new RequestUriPayload(generateClientRegistry(), generateAuthRequest());
        assertThrows(
                RuntimeException.class,
                () -> handler.handleRequest(event, context),
                "Expected to throw exception");
    }

    @Test
    void shouldReturnErrorForInvalidResponseType()
            throws IOException, InterruptedException, JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE_IDTOKEN.toString())
                        .claim("scope", SCOPE)
                        .issuer(CLIENT_ID.getValue())
                        .build();
        setupJwtRequest(jwtClaimsSet);
        var event = new RequestUriPayload(generateClientRegistry(), generateAuthRequest());
        var response = handler.handleRequest(event, context);

        assertFalse(response.isSuccessfulRequest());
        assertThat(response.getErrorObject(), equalTo(OAuth2Error.UNSUPPORTED_RESPONSE_TYPE));
    }

    @Test
    void shouldReturnErrorForUnsupportedScope()
            throws IOException, InterruptedException, JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", "openid profile")
                        .issuer(CLIENT_ID.getValue())
                        .build();
        setupJwtRequest(jwtClaimsSet);
        var event = new RequestUriPayload(generateClientRegistry(), generateAuthRequest());
        var response = handler.handleRequest(event, context);

        assertFalse(response.isSuccessfulRequest());
        assertThat(response.getErrorObject(), equalTo(OAuth2Error.INVALID_SCOPE));
    }

    @Test
    void shouldReturnErrorForUnregisteredScope()
            throws IOException, InterruptedException, JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", "openid email")
                        .issuer(CLIENT_ID.getValue())
                        .build();
        setupJwtRequest(jwtClaimsSet);
        var event = new RequestUriPayload(generateClientRegistry(), generateAuthRequest());
        var response = handler.handleRequest(event, context);

        assertFalse(response.isSuccessfulRequest());
        assertThat(response.getErrorObject(), equalTo(OAuth2Error.INVALID_SCOPE));
    }

    @Test
    void shouldReturnErrorForInvalidAudience()
            throws IOException, InterruptedException, JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience("invalid-audience")
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", "openid")
                        .issuer(CLIENT_ID.getValue())
                        .build();
        setupJwtRequest(jwtClaimsSet);
        var event = new RequestUriPayload(generateClientRegistry(), generateAuthRequest());
        var response = handler.handleRequest(event, context);

        assertFalse(response.isSuccessfulRequest());
        assertThat(response.getErrorObject(), equalTo(OAuth2Error.ACCESS_DENIED));
    }

    @Test
    void shouldReturnErrorForInvalidIssuer()
            throws IOException, InterruptedException, JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", "openid")
                        .issuer("invalid-client")
                        .build();
        setupJwtRequest(jwtClaimsSet);
        var event = new RequestUriPayload(generateClientRegistry(), generateAuthRequest());
        var response = handler.handleRequest(event, context);

        assertFalse(response.isSuccessfulRequest());
        assertThat(response.getErrorObject(), equalTo(OAuth2Error.UNAUTHORIZED_CLIENT));
    }

    @Test
    void shouldReturnErrorIfRequestClaimIsPresentJwt()
            throws IOException, InterruptedException, JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", "openid")
                        .claim("request", "some-random-request-value")
                        .issuer(CLIENT_ID.getValue())
                        .build();
        setupJwtRequest(jwtClaimsSet);
        var event = new RequestUriPayload(generateClientRegistry(), generateAuthRequest());
        var response = handler.handleRequest(event, context);

        assertFalse(response.isSuccessfulRequest());
        assertThat(response.getErrorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
    }

    @Test
    void shouldReturnErrorIfRequestUriClaimIsPresentJwt()
            throws IOException, InterruptedException, JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", "openid")
                        .claim("request_uri", REQUEST_URI)
                        .issuer(CLIENT_ID.getValue())
                        .build();
        setupJwtRequest(jwtClaimsSet);
        var event = new RequestUriPayload(generateClientRegistry(), generateAuthRequest());
        var response = handler.handleRequest(event, context);

        assertFalse(response.isSuccessfulRequest());
        assertThat(response.getErrorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
    }

    @Test
    void shouldThrowWhenUnableToRetrieveRequestJwt() throws IOException, InterruptedException {
        var request = HttpRequest.newBuilder().GET().uri(REQUEST_URI).build();
        when(httpClient.send(request, HttpResponse.BodyHandlers.ofString()))
                .thenThrow(new IOException());
        var event = new RequestUriPayload(generateClientRegistry(), generateAuthRequest());
        assertThrows(
                RuntimeException.class,
                () -> handler.handleRequest(event, context),
                "Expected to throw exception");
    }

    @Test
    void shouldThrowWhenUnableToValidateRequestJwtSignature()
            throws IOException, InterruptedException, JOSEException, NoSuchAlgorithmException {
        var keyPair2 = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .issuer(CLIENT_ID.getValue())
                        .build();
        setupJwtRequest(jwtClaimsSet, keyPair2);
        var event = new RequestUriPayload(generateClientRegistry(), generateAuthRequest());
        assertThrows(
                RuntimeException.class,
                () -> handler.handleRequest(event, context),
                "Expected to throw exception");
    }

    private void setupJwtRequest(JWTClaimsSet jwtClaimsSet)
            throws IOException, InterruptedException, JOSEException {
        setupJwtRequest(jwtClaimsSet, keyPair);
    }

    private void setupJwtRequest(JWTClaimsSet jwtClaimsSet, KeyPair keyPair)
            throws IOException, InterruptedException, JOSEException {
        var jwsHeader = new JWSHeader(JWSAlgorithm.RS256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        var signer = new RSASSASigner(keyPair.getPrivate());
        signedJWT.sign(signer);

        var request = HttpRequest.newBuilder().GET().uri(REQUEST_URI).build();

        when(httpResponse.body()).thenReturn(signedJWT.serialize());
        when(httpClient.send(request, HttpResponse.BodyHandlers.ofString()))
                .thenReturn(httpResponse);
    }

    private ClientRegistry generateClientRegistry() {
        return new ClientRegistry()
                .setClientID(CLIENT_ID.getValue())
                .setPublicKey(
                        Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()))
                .setConsentRequired(false)
                .setClientName("test-client")
                .setScopes(List.of("openid"))
                .setRedirectUrls(singletonList(REDIRECT_URI))
                .setRequestUris(singletonList(REQUEST_URI.toString()))
                .setSectorIdentifierUri("https://test.com")
                .setSubjectType("pairwise");
    }

    private AuthenticationRequest generateAuthRequest() {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        AuthenticationRequest.Builder builder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE, scope, CLIENT_ID, URI.create(REDIRECT_URI))
                        .state(STATE)
                        .nonce(new Nonce())
                        .requestURI(REQUEST_URI);
        return builder.build();
    }
}
