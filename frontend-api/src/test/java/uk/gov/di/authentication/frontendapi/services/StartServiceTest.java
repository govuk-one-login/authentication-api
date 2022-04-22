package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.net.URI;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper.jsonArrayOf;

class StartServiceTest {

    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private static final String EMAIL = "joe.bloggs@example.com";
    private static final ClientID CLIENT_ID = new ClientID("client-id");
    private static final String CLIENT_NAME = "test-client";
    private static final Session SESSION = new Session("a-session-id").setEmailAddress(EMAIL);
    private static final Scope SCOPES =
            new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.OFFLINE_ACCESS);
    private static final String AUDIENCE = "oidc-audience";
    private static final String DOC_APP_SCOPE = "openid doc-checking-app";
    private static final State STATE = new State();

    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private StartService startService;

    @BeforeEach
    void setup() {
        startService = new StartService(dynamoClientService, dynamoService);
    }

    @Test
    void shouldCreateUserContextFromSessionAndClientSession() {
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), CLIENT_ID.getValue(), false)));
        when(dynamoService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(mock(UserProfile.class)));
        var authRequest =
                new AuthenticationRequest.Builder(
                                new ResponseType(ResponseType.Value.CODE),
                                SCOPES,
                                CLIENT_ID,
                                REDIRECT_URI)
                        .state(new State())
                        .nonce(new Nonce())
                        .build();
        var clientSession =
                new ClientSession(
                        authRequest.toParameters(), LocalDateTime.now(), mock(VectorOfTrust.class));
        var userContext = startService.buildUserContext(SESSION, clientSession);

        assertThat(userContext.getSession(), equalTo(SESSION));
        assertThat(userContext.getClientSession(), equalTo(clientSession));
    }

    @ParameterizedTest
    @MethodSource("userStartInfo")
    void shouldCreateUserStartInfo(
            String vtr,
            boolean isIdentityRequired,
            boolean isUpliftRequired,
            boolean clientConsentRequired,
            boolean isConsentRequired,
            String cookieConsent,
            String gaTrackingId,
            boolean isDocCheckingAppUser,
            ClientType clientType,
            SignedJWT signedJWT) {
        var userContext = buildUserContext(vtr, clientConsentRequired, true, clientType, signedJWT);
        var userStartInfo =
                startService.buildUserStartInfo(userContext, cookieConsent, gaTrackingId);

        assertThat(userStartInfo.isUpliftRequired(), equalTo(isUpliftRequired));
        assertThat(userStartInfo.isIdentityRequired(), equalTo(isIdentityRequired));
        assertThat(userStartInfo.isConsentRequired(), equalTo(isConsentRequired));
        assertThat(userStartInfo.getCookieConsent(), equalTo(cookieConsent));
        assertThat(userStartInfo.getGaCrossDomainTrackingId(), equalTo(gaTrackingId));
        assertThat(userStartInfo.isDocCheckingAppUser(), equalTo(isDocCheckingAppUser));
    }

    @ParameterizedTest
    @MethodSource("clientStartInfo")
    void shouldCreateClientStartInfo(boolean cookieConsentShared) throws ParseException {
        var userContext =
                buildUserContext(
                        jsonArrayOf("Cl.Cm"), false, cookieConsentShared, ClientType.WEB, null);

        var clientStartInfo = startService.buildClientStartInfo(userContext);

        assertThat(clientStartInfo.getCookieConsentShared(), equalTo(cookieConsentShared));
        assertThat(clientStartInfo.getClientName(), equalTo(CLIENT_NAME));
        assertThat(clientStartInfo.getScopes(), equalTo(SCOPES.toStringList()));
        assertThat(clientStartInfo.getRedirectUri(), equalTo(REDIRECT_URI));
    }

    @Test
    void shouldReturnGaTrackingIdWhenPresentInAuthRequest() {
        var gaTrackingId = IdGenerator.generate();
        var authRequest =
                new AuthenticationRequest.Builder(
                                new ResponseType(ResponseType.Value.CODE),
                                SCOPES,
                                CLIENT_ID,
                                REDIRECT_URI)
                        .state(new State())
                        .nonce(new Nonce())
                        .customParameter("_ga", gaTrackingId)
                        .build();

        assertThat(startService.getGATrackingId(authRequest.toParameters()), equalTo(gaTrackingId));
    }

    @Test
    void shouldReturnNullWhenGaTrackingIdIsNotPresentInAuthRequest() {
        var authRequest =
                new AuthenticationRequest.Builder(
                                new ResponseType(ResponseType.Value.CODE),
                                SCOPES,
                                CLIENT_ID,
                                REDIRECT_URI)
                        .state(new State())
                        .nonce(new Nonce())
                        .build();

        assertThat(startService.getGATrackingId(authRequest.toParameters()), equalTo(null));
    }

    @ParameterizedTest
    @MethodSource("cookieConsentValues")
    void shouldReturnCookieConsentValueWhenPresentAndValid(
            String cookieConsentValue, boolean cookieConsentShared, String expectedValue) {
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(),
                                        CLIENT_ID.getValue(),
                                        cookieConsentShared)));
        var authRequest =
                new AuthenticationRequest.Builder(
                                new ResponseType(ResponseType.Value.CODE),
                                SCOPES,
                                CLIENT_ID,
                                REDIRECT_URI)
                        .state(new State())
                        .nonce(new Nonce())
                        .customParameter("cookie_consent", cookieConsentValue)
                        .build();

        assertThat(
                startService.getCookieConsentValue(
                        authRequest.toParameters(), CLIENT_ID.getValue()),
                equalTo(expectedValue));
    }

    private static Stream<Arguments> cookieConsentValues() {
        return Stream.of(
                Arguments.of("accept", true, "accept"),
                Arguments.of("reject", true, "reject"),
                Arguments.of("not-engaged", true, "not-engaged"),
                Arguments.of("accept", false, null),
                Arguments.of("reject", false, null),
                Arguments.of("not-engaged", false, null),
                Arguments.of("Accept", true, null),
                Arguments.of("Accept", false, null),
                Arguments.of("", true, null),
                Arguments.of(null, true, null),
                Arguments.of("some-value", true, null));
    }

    private static Stream<Arguments> userStartInfo()
            throws NoSuchAlgorithmException, JOSEException {
        return Stream.of(
                Arguments.of(
                        jsonArrayOf("Cl.Cm"),
                        false,
                        false,
                        false,
                        false,
                        "some-cookie-consent",
                        null,
                        false,
                        ClientType.WEB,
                        null),
                Arguments.of(
                        jsonArrayOf("P2.Cl.Cm"),
                        true,
                        false,
                        true,
                        true,
                        null,
                        "some-ga-tracking-id",
                        false,
                        ClientType.WEB,
                        null),
                Arguments.of(
                        jsonArrayOf("P2.Cl.Cm"),
                        false,
                        false,
                        false,
                        false,
                        null,
                        "some-ga-tracking-id",
                        true,
                        ClientType.APP,
                        generateSignedJWT()));
    }

    private static Stream<Boolean> clientStartInfo() {
        return Stream.of(false, true);
    }

    private ClientRegistry generateClientRegistry(
            String redirectURI, String clientID, boolean cookieConsentShared) {
        return new ClientRegistry()
                .setRedirectUrls(singletonList(redirectURI))
                .setClientID(clientID)
                .setContacts(singletonList("joe.bloggs@digital.cabinet-office.gov.uk"))
                .setPublicKey(null)
                .setScopes(singletonList("openid"))
                .setCookieConsentShared(cookieConsentShared);
    }

    private UserContext buildUserContext(
            String vtrValue,
            boolean consentRequired,
            boolean cookieConsentShared,
            ClientType clientType,
            SignedJWT requestObject) {
        var authRequestBuilder =
                new AuthenticationRequest.Builder(
                                new ResponseType(ResponseType.Value.CODE),
                                SCOPES,
                                CLIENT_ID,
                                REDIRECT_URI)
                        .state(new State())
                        .nonce(new Nonce())
                        .customParameter("vtr", vtrValue);

        if (Objects.nonNull(requestObject)) {
            authRequestBuilder.requestObject(requestObject);
        }
        var clientSession =
                new ClientSession(
                        authRequestBuilder.build().toParameters(),
                        LocalDateTime.now(),
                        VectorOfTrust.getDefaults());
        var clientRegistry =
                new ClientRegistry()
                        .setClientID(CLIENT_ID.getValue())
                        .setClientName(CLIENT_NAME)
                        .setConsentRequired(consentRequired)
                        .setCookieConsentShared(cookieConsentShared)
                        .setClientType(clientType.getValue());
        return UserContext.builder(SESSION)
                .withClientSession(clientSession)
                .withClient(clientRegistry)
                .build();
    }

    private static SignedJWT generateSignedJWT() throws NoSuchAlgorithmException, JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", DOC_APP_SCOPE)
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("state", STATE)
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        var jwsHeader = new JWSHeader(JWSAlgorithm.RS256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        var signer = new RSASSASigner(keyPair.getPrivate());
        signedJWT.sign(signer);
        return signedJWT;
    }
}
