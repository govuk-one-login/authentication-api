package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.net.URI;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
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
import static uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper.jsonArrayOf;

class StartServiceTest {

    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private static final String EMAIL = CommonTestVariables.EMAIL;
    private static final ClientID CLIENT_ID = new ClientID("client-id");
    private static final String CLIENT_NAME = "test-client";
    private static final String SESSION_ID = "a-session-id";
    private static final AuthSessionItem AUTH_SESSION =
            new AuthSessionItem()
                    .withEmailAddress(EMAIL)
                    .withSessionId(SESSION_ID)
                    .withClientId(CLIENT_ID.getValue());
    private static final Scope SCOPES =
            new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.OFFLINE_ACCESS);
    private static final String AUDIENCE = "oidc-audience";
    private static final Scope DOC_APP_SCOPES =
            new Scope(OIDCScopeValue.OPENID, CustomScopeValue.DOC_CHECKING_APP);
    private static final State STATE = new State();
    private final UserContext basicUserContext =
            buildUserContext(true, ClientType.WEB, true, Optional.empty(), Optional.empty(), false);

    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private StartService startService;

    @BeforeEach
    void setup() {
        startService = new StartService(dynamoClientService, dynamoService);
    }

    @Test
    void shouldCreateUserContextFromSessionAndAuthSession() {
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), CLIENT_ID.getValue(), false)));
        when(dynamoService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(mock(UserProfile.class)));
        when(dynamoService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn((mock(UserCredentials.class)));
        var userContext = startService.buildUserContext(AUTH_SESSION);

        assertThat(userContext.getAuthSession(), equalTo(AUTH_SESSION));
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
                Arguments.of("some-cookie-consent", null, false, false),
                Arguments.of(null, "ga-tracking-id", false, true));
    }

    @ParameterizedTest
    @MethodSource("userStartInfo")
    void shouldCreateUserStartInfo(
            String cookieConsent,
            String gaTrackingId,
            boolean rpSupportsIdentity,
            boolean isAuthenticated) {
        var userContext =
                buildUserContext(
                        true,
                        ClientType.WEB,
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
                        cookieConsent,
                        gaTrackingId,
                        false,
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

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void shouldCreateUserStartInfoWithCorrectReauthBlockedValue(boolean isBlockedForReauth) {
        when(configurationService.isAuthenticationAttemptsServiceEnabled()).thenReturn(true);
        var maxRetries = 6;
        when(configurationService.getMaxPasswordRetries()).thenReturn(maxRetries);

        var userStartInfo =
                startService.buildUserStartInfo(
                        basicUserContext,
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
                        CredentialTrustLevel.LOW_LEVEL,
                        true,
                        authAppUserProfileVerified,
                        authAppUserCredentialsVerified),
                Arguments.of(
                        jsonArrayOf("Cl.Cm"),
                        null,
                        false,
                        authAppUserProfileUnverified,
                        authAppUserCredentialsUnverified),
                Arguments.of(
                        jsonArrayOf("Cl.Cm"),
                        CredentialTrustLevel.LOW_LEVEL,
                        true,
                        smsUserProfileVerified,
                        smsUserCredentialsVerified),
                Arguments.of(
                        jsonArrayOf("Cl.Cm"),
                        null,
                        false,
                        smsUserProfileUnverified,
                        smsUserCredentialsUnverified),
                Arguments.of(
                        jsonArrayOf("Cl.Cm"),
                        null,
                        false,
                        unverifiedUserProfile,
                        unverifiedUserCredentials),
                Arguments.of(
                        jsonArrayOf("Cl"),
                        CredentialTrustLevel.LOW_LEVEL,
                        false,
                        authAppUserProfileVerified,
                        authAppUserCredentialsVerified),
                Arguments.of(
                        jsonArrayOf("Cl.Cm"),
                        CredentialTrustLevel.MEDIUM_LEVEL,
                        false,
                        authAppUserProfileVerified,
                        authAppUserCredentialsVerified),
                Arguments.of(
                        jsonArrayOf("P2.Cl.Cm"),
                        CredentialTrustLevel.MEDIUM_LEVEL,
                        false,
                        authAppUserProfileVerified,
                        authAppUserCredentialsVerified));
    }

    @Test
    void shouldCreateUserStartInfoWithAuthenticatedFalseWhenReauthenticationIsTrue() {
        withUserProfile();

        var userStartInfo =
                startService.buildUserStartInfo(
                        basicUserContext,
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
            String vtrString,
            CredentialTrustLevel credentialTrustLevel,
            boolean expectedUpliftRequiredValue,
            UserProfile userProfile,
            UserCredentials userCredentials) {
        var userContext =
                buildUserContext(
                        true,
                        ClientType.WEB,
                        true,
                        Optional.of(userProfile),
                        Optional.of(userCredentials),
                        false);
        var requestedVtr =
                VectorOfTrust.parseFromAuthRequestAttribute(Collections.singletonList(vtrString));
        var requestedCredentialTrustLevel = requestedVtr.getCredentialTrustLevel();
        var upliftRequired =
                startService.isUpliftRequired(requestedCredentialTrustLevel, credentialTrustLevel);
        var userStartInfo =
                startService.buildUserStartInfo(
                        userContext,
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
                        true,
                        ClientType.WEB,
                        true,
                        Optional.of(userProfile),
                        Optional.of(userCredentials),
                        false);

        var userStartInfo =
                startService.buildUserStartInfo(
                        userContext, "true", "tracking-id", true, false, false, false, false);

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
                        true,
                        ClientType.WEB,
                        true,
                        Optional.of(userProfile),
                        userCredentials,
                        false);

        var userStartInfo =
                startService.buildUserStartInfo(
                        userContext, "true", "tracking-id", true, false, false, false, false);

        assertThat(userStartInfo.mfaMethodType(), equalTo(MFAMethodType.NONE));
    }

    @ParameterizedTest
    @MethodSource("clientStartInfo")
    void shouldCreateClientStartInfo(
            boolean cookieConsentShared, SignedJWT signedJWT, boolean oneLoginService) {
        var scopes = Objects.nonNull(signedJWT) ? DOC_APP_SCOPES : SCOPES;

        var clientStartInfo =
                startService.buildClientStartInfo(
                        ServiceType.MANDATORY.toString(),
                        CLIENT_NAME,
                        scopes.toStringList(),
                        REDIRECT_URI,
                        STATE,
                        cookieConsentShared,
                        oneLoginService);

        assertThat(clientStartInfo.cookieConsentShared(), equalTo(cookieConsentShared));
        assertThat(clientStartInfo.clientName(), equalTo(CLIENT_NAME));
        assertThat(clientStartInfo.redirectUri(), equalTo(REDIRECT_URI));
        assertThat(clientStartInfo.state().getValue(), equalTo(STATE.getValue()));
        assertThat(clientStartInfo.isOneLoginService(), equalTo(oneLoginService));
        assertThat(clientStartInfo.serviceType(), equalTo(ServiceType.MANDATORY.toString()));

        var expectedScopes = SCOPES;
        if (Objects.nonNull(signedJWT)) {
            expectedScopes = DOC_APP_SCOPES;
        }
        assertThat(clientStartInfo.scopes(), equalTo(expectedScopes.toStringList()));
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

        assertThat(
                startService.getCookieConsentValue(cookieConsentValue, cookieConsentShared),
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
                Arguments.of(false, null, false),
                Arguments.of(true, null, false),
                Arguments.of(true, null, true),
                Arguments.of(true, generateSignedJWT(), false));
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
            boolean cookieConsentShared,
            ClientType clientType,
            boolean identityVerificationSupport,
            Optional<UserProfile> userProfile,
            Optional<UserCredentials> userCredentials,
            boolean oneLoginService) {
        return buildUserContext(
                cookieConsentShared,
                clientType,
                identityVerificationSupport,
                userProfile,
                userCredentials,
                oneLoginService,
                Optional.empty());
    }

    private UserContext buildUserContext(
            boolean cookieConsentShared,
            ClientType clientType,
            boolean identityVerificationSupport,
            Optional<UserProfile> userProfile,
            Optional<UserCredentials> userCredentials,
            boolean oneLoginService,
            Optional<String> serviceTypeOpt) {
        var clientRegistry =
                new ClientRegistry()
                        .withClientID(CLIENT_ID.getValue())
                        .withClientName(CLIENT_NAME)
                        .withCookieConsentShared(cookieConsentShared)
                        .withClientType(clientType.getValue())
                        .withIdentityVerificationSupported(identityVerificationSupport)
                        .withOneLoginService(oneLoginService);
        serviceTypeOpt.ifPresent(clientRegistry::setServiceType);
        return UserContext.builder(AUTH_SESSION)
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
