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
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.entity.LevelOfConfidence;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.net.URI;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.LevelOfConfidence.NONE;
import static uk.gov.di.authentication.shared.entity.LevelOfConfidence.retrieveLevelOfConfidence;
import static uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper.jsonArrayOf;

class StartServiceTest {

    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private static final String EMAIL = CommonTestVariables.EMAIL;
    private static final ClientID CLIENT_ID = new ClientID("client-id");
    private static final String CLIENT_NAME = "test-client";
    private static final String SESSION_ID = "a-session-id";
    private static final Session SESSION = new Session();
    private static final AuthSessionItem AUTH_SESSION =
            new AuthSessionItem().withEmailAddress(EMAIL).withSessionId(SESSION_ID);
    private static final Scope SCOPES =
            new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.OFFLINE_ACCESS);
    private static final String AUDIENCE = "oidc-audience";
    private static final Scope DOC_APP_SCOPES =
            new Scope(OIDCScopeValue.OPENID, CustomScopeValue.DOC_CHECKING_APP);
    private static final State STATE = new State();
    private final UserContext basicUserContext =
            buildUserContext(
                    jsonArrayOf("P2.Cl.Cm"),
                    true,
                    ClientType.WEB,
                    null,
                    true,
                    Optional.empty(),
                    Optional.empty(),
                    false);

    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private StartService startService;

    @BeforeEach
    void setup() {
        startService = new StartService(dynamoClientService, dynamoService, sessionService);
    }

    @Test
    void shouldCreateUserContextFromSessionAuthSessionAndClientSession() {
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), CLIENT_ID.getValue(), false)));
        when(dynamoService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(mock(UserProfile.class)));
        when(dynamoService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn((mock(UserCredentials.class)));
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
                        authRequest.toParameters(),
                        LocalDateTime.now(),
                        mock(VectorOfTrust.class),
                        CLIENT_NAME);
        var userContext = startService.buildUserContext(SESSION, clientSession, AUTH_SESSION);

        assertThat(userContext.getSession(), equalTo(SESSION));
        assertThat(userContext.getAuthSession(), equalTo(AUTH_SESSION));
        assertThat(userContext.getClientSession(), equalTo(clientSession));
    }

    @Test
    void returnsFalseIfUserProfilePresent() {
        withUserProfile();
        assertFalse(startService.isUserProfileEmpty(AUTH_SESSION));
    }

    @Test
    void returnsTrueWhenUserProfileEmpty() {
        withNoUserProfile();
        assertTrue(startService.isUserProfileEmpty(AUTH_SESSION));
    }

    private static Stream<Arguments> userStartInfo() {
        return Stream.of(
                Arguments.of(jsonArrayOf("Cl"), "some-cookie-consent", null, false, false),
                Arguments.of(jsonArrayOf("Cl.Cm"), null, "ga-tracking-id", false, true));
    }

    @ParameterizedTest
    @MethodSource("userStartInfo")
    void shouldCreateUserStartInfo(
            String vtr,
            String cookieConsent,
            String gaTrackingId,
            boolean rpSupportsIdentity,
            boolean isAuthenticated) {
        var userContext =
                buildUserContext(
                        vtr,
                        true,
                        ClientType.WEB,
                        null,
                        rpSupportsIdentity,
                        Optional.of(
                                new UserProfile()
                                        .withSubjectID(new Subject().getValue())
                                        .withEmail(EMAIL)),
                        Optional.empty(),
                        false);
        var userStartInfo =
                startService.buildUserStartInfo(
                        userContext,
                        LevelOfConfidence.NONE,
                        cookieConsent,
                        gaTrackingId,
                        true,
                        false,
                        false,
                        isAuthenticated,
                        false);

        assertThat(userStartInfo.isUpliftRequired(), equalTo(false));
        assertThat(userStartInfo.isIdentityRequired(), equalTo(false));
        assertThat(userStartInfo.cookieConsent(), equalTo(cookieConsent));
        assertThat(userStartInfo.gaCrossDomainTrackingId(), equalTo(gaTrackingId));
        assertThat(userStartInfo.isAuthenticated(), equalTo(isAuthenticated));
        assertThat(userStartInfo.isBlockedForReauth(), equalTo(false));
    }

    private static Stream<Arguments> userStartIdentityInfo() {
        return Stream.of(
                Arguments.of(jsonArrayOf("P2.Cl.Cm"), "P2", true, true, true),
                Arguments.of(jsonArrayOf("Cl.Cm"), "P0", false, true, true),
                Arguments.of(jsonArrayOf("P2.Cl.Cm"), "P2", false, false, true),
                Arguments.of(jsonArrayOf("P2.Cl.Cm"), "P2", true, true, true),
                Arguments.of(jsonArrayOf("P2.Cl.Cm"), "P2", false, true, false),
                Arguments.of(jsonArrayOf("P2.Cl.Cm"), "P2", false, false, false));
    }

    @ParameterizedTest
    @MethodSource("userStartIdentityInfo")
    void shouldCreateUserStartInfoWithCorrectIdentityRequiredValue(
            String vtr,
            String levelOfConfidence,
            boolean expectedIdentityRequiredValue,
            boolean rpSupportsIdentity,
            boolean identityEnabled) {
        var userContext =
                buildUserContext(
                        vtr,
                        true,
                        ClientType.WEB,
                        null,
                        rpSupportsIdentity,
                        Optional.empty(),
                        Optional.empty(),
                        false);
        var userStartInfo =
                startService.buildUserStartInfo(
                        userContext,
                        retrieveLevelOfConfidence(levelOfConfidence),
                        "some-cookie-consent",
                        "some-ga-tracking-id",
                        identityEnabled,
                        false,
                        false,
                        false,
                        false);

        assertThat(userStartInfo.isIdentityRequired(), equalTo(expectedIdentityRequiredValue));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void shouldCreateUserStartInfoWithCorrectReauthBlockedValue(boolean isBlockedForReauth) {
        when(configurationService.isAuthenticationAttemptsServiceEnabled()).thenReturn(true);
        var maxRetries = 6;
        when(configurationService.getMaxPasswordRetries()).thenReturn(maxRetries);

        var userStartInfo =
                startService.buildUserStartInfo(
                        basicUserContext,
                        NONE,
                        "some-cookie-consent",
                        "some-ga-tracking-id",
                        true,
                        false,
                        isBlockedForReauth,
                        false,
                        false);

        assertThat(userStartInfo.isBlockedForReauth(), equalTo(isBlockedForReauth));
    }

    private static Stream<Arguments> userStartUpliftInfo() {
        var authAppUserCredentialsVerified =
                new UserCredentials()
                        .withEmail(EMAIL)
                        .setMfaMethod(
                                (new MFAMethod(
                                        MFAMethodType.AUTH_APP.getValue(),
                                        "rubbish-value",
                                        true,
                                        true,
                                        NowHelper.nowMinus(50, ChronoUnit.DAYS).toString())));
        var authAppUserProfileVerified = new UserProfile().withEmail(EMAIL).withAccountVerified(1);

        var authAppUserCredentialsUnverified =
                new UserCredentials()
                        .withEmail(EMAIL)
                        .setMfaMethod(
                                (new MFAMethod(
                                        MFAMethodType.AUTH_APP.getValue(),
                                        "rubbish-value",
                                        false,
                                        true,
                                        NowHelper.nowMinus(50, ChronoUnit.DAYS).toString())));
        var authAppUserProfileUnverified =
                new UserProfile().withEmail(EMAIL).withAccountVerified(0);

        var smsUserCredentialsVerified = new UserCredentials().withEmail(EMAIL);
        var smsUserProfileVerified =
                new UserProfile()
                        .withEmail(EMAIL)
                        .withAccountVerified(1)
                        .withPhoneNumber("+447316763843")
                        .withPhoneNumberVerified(true);

        var smsUserCredentialsUnverified = new UserCredentials().withEmail(EMAIL);
        var smsUserProfileUnverified =
                new UserProfile()
                        .withEmail(EMAIL)
                        .withAccountVerified(0)
                        .withPhoneNumber("+447316763843")
                        .withPhoneNumberVerified(false);

        var unverifiedUserCredentials = new UserCredentials().withEmail(EMAIL);
        var unverifiedUserProfile =
                new UserProfile()
                        .withEmail(EMAIL)
                        .withAccountVerified(0)
                        .withPhoneNumberVerified(false);

        return Stream.of(
                Arguments.of(
                        jsonArrayOf("Cl.Cm"),
                        false,
                        CredentialTrustLevel.LOW_LEVEL,
                        true,
                        authAppUserProfileVerified,
                        authAppUserCredentialsVerified,
                        MFAMethodType.AUTH_APP),
                Arguments.of(
                        jsonArrayOf("Cl.Cm"),
                        false,
                        null,
                        false,
                        authAppUserProfileUnverified,
                        authAppUserCredentialsUnverified,
                        null),
                Arguments.of(
                        jsonArrayOf("Cl.Cm"),
                        false,
                        CredentialTrustLevel.LOW_LEVEL,
                        true,
                        smsUserProfileVerified,
                        smsUserCredentialsVerified,
                        MFAMethodType.SMS),
                Arguments.of(
                        jsonArrayOf("Cl.Cm"),
                        false,
                        null,
                        false,
                        smsUserProfileUnverified,
                        smsUserCredentialsUnverified,
                        null),
                Arguments.of(
                        jsonArrayOf("Cl.Cm"),
                        false,
                        null,
                        false,
                        unverifiedUserProfile,
                        unverifiedUserCredentials,
                        null),
                Arguments.of(
                        jsonArrayOf("Cl"),
                        false,
                        CredentialTrustLevel.LOW_LEVEL,
                        false,
                        authAppUserProfileVerified,
                        authAppUserCredentialsVerified,
                        MFAMethodType.AUTH_APP),
                Arguments.of(
                        jsonArrayOf("Cl.Cm"),
                        false,
                        CredentialTrustLevel.MEDIUM_LEVEL,
                        false,
                        authAppUserProfileVerified,
                        authAppUserCredentialsVerified,
                        MFAMethodType.AUTH_APP),
                Arguments.of(
                        jsonArrayOf("P2.Cl.Cm"),
                        true,
                        CredentialTrustLevel.MEDIUM_LEVEL,
                        false,
                        authAppUserProfileVerified,
                        authAppUserCredentialsVerified,
                        MFAMethodType.AUTH_APP));
    }

    @Test
    void shouldCreateUserStartInfoWithAuthenticatedFalseWhenReauthenticationIsTrue() {
        withUserProfile();

        var userStartInfo =
                startService.buildUserStartInfo(
                        basicUserContext,
                        NONE,
                        "some-cookie-consent",
                        "some-ga-tracking-id",
                        true,
                        true,
                        false,
                        true,
                        false);

        assertThat(userStartInfo.isAuthenticated(), equalTo(false));
    }

    @ParameterizedTest
    @MethodSource("userStartUpliftInfo")
    void shouldCreateUserStartInfoWithCorrectUpliftRequiredValue(
            String vtr,
            boolean expectedIdentityRequiredValue,
            CredentialTrustLevel credentialTrustLevel,
            boolean expectedUpliftRequiredValue,
            UserProfile userProfile,
            UserCredentials userCredentials,
            MFAMethodType expectedMfaMethodType) {
        var userContext =
                buildUserContext(
                        vtr,
                        true,
                        ClientType.WEB,
                        null,
                        true,
                        Optional.of(userProfile),
                        Optional.of(userCredentials),
                        false);
        var levelOfConfidence =
                VectorOfTrust.parseFromAuthRequestAttribute(Collections.singletonList(vtr))
                        .getLevelOfConfidence();
        var upliftRequired =
                startService.isUpliftRequired(userContext.getClientSession(), credentialTrustLevel);
        var userStartInfo =
                startService.buildUserStartInfo(
                        userContext,
                        levelOfConfidence,
                        "some-cookie-consent",
                        "some-ga-tracking-id",
                        true,
                        false,
                        false,
                        false,
                        upliftRequired);

        assertThat(userStartInfo.isUpliftRequired(), equalTo(expectedUpliftRequiredValue));
    }

    private static Stream<Arguments> mfaMethodsForMigratedUserToExpectedMfaMethodType() {
        var defaultAuthApp =
                MFAMethod.authAppMfaMethod(
                        "some-credential-1",
                        true,
                        true,
                        PriorityIdentifier.DEFAULT,
                        "auth-app-id-1");
        var backupAuthApp =
                MFAMethod.authAppMfaMethod(
                        "some-credential-2",
                        true,
                        true,
                        PriorityIdentifier.BACKUP,
                        "auth-app-id-2");
        var defaultSmsMethod =
                MFAMethod.smsMfaMethod(
                        true, true, "+447900000000", PriorityIdentifier.DEFAULT, "sms-id-1");
        var backupSmsMethod =
                MFAMethod.smsMfaMethod(
                        true, true, "+447900000100", PriorityIdentifier.BACKUP, "sms-id-2");
        var nonMigratedNonEnabledAuthApp =
                new MFAMethod(
                        MFAMethodType.AUTH_APP.name(),
                        "another-credential",
                        true,
                        false,
                        "updated-at");
        var nonMigratedNonVerifiedAuthApp =
                new MFAMethod(
                        MFAMethodType.AUTH_APP.name(),
                        "another-credential",
                        false,
                        true,
                        "updated-at");
        return Stream.of(
                Arguments.of(List.of(defaultAuthApp, backupSmsMethod), MFAMethodType.AUTH_APP),
                Arguments.of(List.of(defaultSmsMethod, backupAuthApp), MFAMethodType.SMS),
                Arguments.of(List.of(defaultSmsMethod, backupSmsMethod), MFAMethodType.SMS),
                Arguments.of(
                        List.of(defaultSmsMethod, nonMigratedNonEnabledAuthApp), MFAMethodType.SMS),
                Arguments.of(List.of(nonMigratedNonEnabledAuthApp), MFAMethodType.NONE),
                Arguments.of(List.of(nonMigratedNonVerifiedAuthApp), MFAMethodType.NONE),
                Arguments.of(List.of(), MFAMethodType.NONE));
    }

    @ParameterizedTest
    @MethodSource("mfaMethodsForMigratedUserToExpectedMfaMethodType")
    void shouldCreateStartInfoWithCorrectMfaMethodTypeForAMigratedUser(
            List<MFAMethod> mfaMethods, MFAMethodType expectedMfaMethodType) {
        var userProfile =
                new UserProfile()
                        .withMfaMethodsMigrated(true)
                        .withEmail(EMAIL)
                        .withPhoneNumberVerified(false);
        var userCredentials = new UserCredentials().withEmail(EMAIL).withMfaMethods(mfaMethods);
        var userContext =
                buildUserContext(
                        jsonArrayOf("Cl.Cm"),
                        true,
                        ClientType.WEB,
                        null,
                        true,
                        Optional.of(userProfile),
                        Optional.of(userCredentials),
                        false);

        var userStartInfo =
                startService.buildUserStartInfo(
                        userContext, NONE, "true", "tracking-id", true, false, false, false, false);

        assertThat(userStartInfo.mfaMethodType(), equalTo(expectedMfaMethodType));
    }

    @Test
    void shouldReturnNoneIfMigratedUserDoesNotHaveUserCredentials() {
        var userProfile =
                new UserProfile()
                        .withMfaMethodsMigrated(true)
                        .withEmail(EMAIL)
                        .withPhoneNumberVerified(false);
        var userCredentials = Optional.<UserCredentials>empty();
        var userContext =
                buildUserContext(
                        jsonArrayOf("Cl.Cm"),
                        true,
                        ClientType.WEB,
                        null,
                        true,
                        Optional.of(userProfile),
                        userCredentials,
                        false);

        var userStartInfo =
                startService.buildUserStartInfo(
                        userContext, NONE, "true", "tracking-id", true, false, false, false, false);

        assertThat(userStartInfo.mfaMethodType(), equalTo(MFAMethodType.NONE));
    }

    @ParameterizedTest
    @MethodSource("clientStartInfo")
    void shouldCreateClientStartInfo(
            boolean cookieConsentShared,
            ClientType clientType,
            SignedJWT signedJWT,
            boolean oneLoginService)
            throws ParseException {
        var userContext =
                buildUserContext(
                        jsonArrayOf("Cl.Cm"),
                        cookieConsentShared,
                        clientType,
                        signedJWT,
                        false,
                        Optional.empty(),
                        Optional.empty(),
                        oneLoginService);

        var clientStartInfo = startService.buildClientStartInfo(userContext);

        assertThat(clientStartInfo.cookieConsentShared(), equalTo(cookieConsentShared));
        assertThat(clientStartInfo.clientName(), equalTo(CLIENT_NAME));
        assertThat(clientStartInfo.redirectUri(), equalTo(REDIRECT_URI));
        assertThat(clientStartInfo.state().getValue(), equalTo(STATE.getValue()));
        assertThat(clientStartInfo.isOneLoginService(), equalTo(oneLoginService));

        var expectedScopes = SCOPES;
        if (Objects.nonNull(signedJWT)) {
            expectedScopes = DOC_APP_SCOPES;
        }
        assertThat(clientStartInfo.scopes(), equalTo(expectedScopes.toStringList()));
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

    private static Stream<Arguments> clientStartInfo()
            throws NoSuchAlgorithmException, JOSEException {
        return Stream.of(
                Arguments.of(false, ClientType.WEB, null, false),
                Arguments.of(true, ClientType.WEB, null, false),
                Arguments.of(true, ClientType.WEB, null, true),
                Arguments.of(true, ClientType.APP, generateSignedJWT(), false));
    }

    private ClientRegistry generateClientRegistry(
            String redirectURI, String clientID, boolean cookieConsentShared) {
        return new ClientRegistry()
                .withRedirectUrls(singletonList(redirectURI))
                .withClientID(clientID)
                .withContacts(singletonList("joe.bloggs@digital.cabinet-office.gov.uk"))
                .withPublicKey(null)
                .withScopes(singletonList("openid"))
                .withCookieConsentShared(cookieConsentShared);
    }

    private UserContext buildUserContext(
            String vtrValue,
            boolean cookieConsentShared,
            ClientType clientType,
            SignedJWT requestObject,
            boolean identityVerificationSupport,
            Optional<UserProfile> userProfile,
            Optional<UserCredentials> userCredentials,
            boolean oneLoginService) {
        AuthenticationRequest authRequest;
        var clientSessionVTR = VectorOfTrust.getDefaults();
        if (Objects.nonNull(requestObject)) {
            authRequest =
                    new AuthenticationRequest.Builder(
                                    new ResponseType(ResponseType.Value.CODE),
                                    DOC_APP_SCOPES,
                                    CLIENT_ID,
                                    REDIRECT_URI)
                            .state(STATE)
                            .nonce(new Nonce())
                            .requestObject(requestObject)
                            .build();
        } else {
            clientSessionVTR =
                    VectorOfTrust.parseFromAuthRequestAttribute(
                            Collections.singletonList(vtrValue));
            authRequest =
                    new AuthenticationRequest.Builder(
                                    new ResponseType(ResponseType.Value.CODE),
                                    SCOPES,
                                    CLIENT_ID,
                                    REDIRECT_URI)
                            .state(STATE)
                            .nonce(new Nonce())
                            .customParameter("vtr", vtrValue)
                            .build();
        }
        var clientSession =
                new ClientSession(
                        authRequest.toParameters(),
                        LocalDateTime.now(),
                        clientSessionVTR,
                        CLIENT_NAME);
        var clientRegistry =
                new ClientRegistry()
                        .withClientID(CLIENT_ID.getValue())
                        .withClientName(CLIENT_NAME)
                        .withCookieConsentShared(cookieConsentShared)
                        .withClientType(clientType.getValue())
                        .withIdentityVerificationSupported(identityVerificationSupport)
                        .withOneLoginService(oneLoginService);
        return UserContext.builder(SESSION)
                .withClientSession(clientSession)
                .withClient(clientRegistry)
                .withUserCredentials(userCredentials)
                .withUserProfile(userProfile)
                .build();
    }

    private static SignedJWT generateSignedJWT() throws NoSuchAlgorithmException, JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI.toString())
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", DOC_APP_SCOPES.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("state", STATE.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        var jwsHeader = new JWSHeader(JWSAlgorithm.RS256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        var signer = new RSASSASigner(keyPair.getPrivate());
        signedJWT.sign(signer);
        return signedJWT;
    }

    private void withUserProfile() {
        when(dynamoService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(
                        Optional.of(
                                new UserProfile()
                                        .withEmail(EMAIL)
                                        .withSubjectID(new Subject().getValue())));
    }

    private void withNoUserProfile() {
        when(dynamoService.getUserProfileByEmailMaybe(EMAIL)).thenReturn(Optional.empty());
    }
}
