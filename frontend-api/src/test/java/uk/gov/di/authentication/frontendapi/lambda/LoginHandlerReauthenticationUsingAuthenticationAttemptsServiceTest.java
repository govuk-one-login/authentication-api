package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables;
import uk.gov.di.authentication.frontendapi.services.UserMigrationService;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.MFAMethod;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Objects.nonNull;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.longThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.INVALID_CREDENTIALS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_PASSWORD;
import static uk.gov.di.authentication.shared.entity.JourneyType.REAUTHENTICATION;
import static uk.gov.di.authentication.shared.entity.MFAMethodType.SMS;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper.jsonArrayOf;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class LoginHandlerReauthenticationUsingAuthenticationAttemptsServiceTest {

    private static final String EMAIL = CommonTestVariables.EMAIL;
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    public static final int MAX_ALLOWED_PASSWORD_RETRIES = 6;
    private final UserCredentials userCredentials =
            new UserCredentials().withEmail(EMAIL).withPassword(CommonTestVariables.PASSWORD);

    private final UserCredentials userCredentialsAuthApp =
            new UserCredentials()
                    .withEmail(EMAIL)
                    .withPassword(CommonTestVariables.PASSWORD)
                    .setMfaMethod(AUTH_APP_MFA_METHOD);
    private static final ClientID CLIENT_ID = new ClientID();
    private static final String CLIENT_NAME = "client-name";
    private static final Subject INTERNAL_SUBJECT_ID = new Subject();
    private static final byte[] SALT = SaltHelper.generateNewSalt();
    private static final MFAMethod AUTH_APP_MFA_METHOD =
            new MFAMethod()
                    .withMfaMethodType(MFAMethodType.AUTH_APP.getValue())
                    .withMethodVerified(true)
                    .withEnabled(true);
    private static final Session session = new Session(SESSION_ID).setEmailAddress(EMAIL);
    private final Context context = mock(Context.class);
    private final String expectedCommonSubject =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    INTERNAL_SUBJECT_ID.getValue(), "test.account.gov.uk", SALT);

    private final String validBodyWithReauthJourney =
            format(
                    "{ \"password\": \"%s\", \"email\": \"%s\", \"journeyType\": \"%s\"}",
                    CommonTestVariables.PASSWORD, EMAIL.toUpperCase(), REAUTHENTICATION);

    private final AuditContext auditContextWithAllUserInfo =
            new AuditContext(
                    CLIENT_ID.getValue(),
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    expectedCommonSubject,
                    EMAIL,
                    IP_ADDRESS,
                    CommonTestVariables.UK_MOBILE_NUMBER,
                    DI_PERSISTENT_SESSION_ID,
                    Optional.empty());

    private LoginHandler handler;

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientSession clientSession = mock(ClientSession.class);
    private final ClientService clientService = mock(ClientService.class);
    private final UserMigrationService userMigrationService = mock(UserMigrationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final CommonPasswordsService commonPasswordsService =
            mock(CommonPasswordsService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final AuthenticationAttemptsService authenticationAttemptsService =
            mock(AuthenticationAttemptsService.class);

    @RegisterExtension
    private final CaptureLoggingExtension logging = new CaptureLoggingExtension(LoginHandler.class);

    @AfterEach
    void tearDown() {
        assertThat(logging.events(), not(hasItem(withMessageContaining(SESSION_ID))));
    }

    @BeforeEach
    void setUp() {
        when(configurationService.getMaxPasswordRetries()).thenReturn(MAX_ALLOWED_PASSWORD_RETRIES);
        when(configurationService.getTermsAndConditionsVersion()).thenReturn("1.0");
        when(configurationService.getInternalSectorUri()).thenReturn(INTERNAL_SECTOR_URI);
        when(configurationService.isAuthenticationAttemptsServiceEnabled()).thenReturn(true);

        when(clientSessionService.getClientSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(clientSession));

        when(context.getAwsRequestId()).thenReturn("aws-session-id");

        when(clientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(generateClientRegistry()));

        when(authenticationService.getOrGenerateSalt(any(UserProfile.class))).thenReturn(SALT);

        handler =
                new LoginHandler(
                        configurationService,
                        sessionService,
                        authenticationService,
                        clientSessionService,
                        clientService,
                        codeStorageService,
                        userMigrationService,
                        auditService,
                        cloudwatchMetricsService,
                        commonPasswordsService,
                        authenticationAttemptsService);
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldReturnErrorAndNotLockUserAccountOutAfterMaxNumberOfIncorrectPasswordsPresented(
            MFAMethodType mfaMethodType) {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(clientSession.getAuthRequestParams()).thenReturn(generateAuthRequest().toParameters());
        var maxRetriesAllowed = configurationService.getMaxPasswordRetries();

        when(authenticationAttemptsService.getCount(any(), any(), any()))
                .thenReturn(maxRetriesAllowed - 1);

        when(configurationService.supportReauthSignoutEnabled()).thenReturn(true);

        usingValidSession();
        usingApplicableUserCredentialsWithLogin(mfaMethodType, false);
        usingDefaultVectorOfTrust();

        var event = eventWithHeadersAndBody(VALID_HEADERS, validBodyWithReauthJourney);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1028));

        verify(authenticationAttemptsService).getCount(any(), any(), any());
        verify(authenticationAttemptsService).deleteCount(any(), any(), any());

        verify(auditService)
                .submitAuditEvent(
                        INVALID_CREDENTIALS,
                        auditContextWithAllUserInfo.withTxmaAuditEncoded(
                                Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("internalSubjectId", userProfile.getSubjectID()),
                        pair(
                                "incorrectPasswordCount",
                                configurationService.getMaxPasswordRetries()),
                        pair("attemptNoFailedAt", configurationService.getMaxPasswordRetries()));

        verifyNoInteractions(cloudwatchMetricsService);
        verify(sessionService, never()).save(any());
    }

    @Test
    void shouldIncrementRelevantCountWhenCredentialsAreInvalid() {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        usingApplicableUserCredentialsWithLogin(SMS, false);

        when(configurationService.supportReauthSignoutEnabled()).thenReturn(true);
        when(configurationService.getReauthEnterPasswordCountTTL()).thenReturn(120l);

        when(authenticationAttemptsService.getCount(any(), any(), any())).thenReturn(1);

        usingValidSession();
        usingDefaultVectorOfTrust();

        var event = eventWithHeadersAndBody(VALID_HEADERS, validBodyWithReauthJourney);

        handler.handleRequest(event, context);

        verify(authenticationAttemptsService)
                .getCount(userProfile.getSubjectID(), REAUTHENTICATION, ENTER_PASSWORD);

        verify(authenticationAttemptsService)
                .createOrIncrementCount(
                        eq(userProfile.getSubjectID()),
                        longThat(
                                ttl -> {
                                    long expectedMin =
                                            NowHelper.nowPlus(120, ChronoUnit.SECONDS)
                                                            .toInstant()
                                                            .getEpochSecond()
                                                    - 1;
                                    long expectedMax =
                                            NowHelper.nowPlus(120, ChronoUnit.SECONDS)
                                                            .toInstant()
                                                            .getEpochSecond()
                                                    + 1;
                                    return ttl >= expectedMin && ttl <= expectedMax;
                                }),
                        eq(REAUTHENTICATION),
                        eq(ENTER_PASSWORD));
    }

    private AuthenticationRequest generateAuthRequest() {
        return generateAuthRequest(null);
    }

    private AuthenticationRequest generateAuthRequest(CredentialTrustLevel credentialTrustLevel) {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        AuthenticationRequest.Builder builder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                scope,
                                CLIENT_ID,
                                URI.create("http://localhost/redirect"))
                        .state(new State())
                        .nonce(new Nonce());
        if (nonNull(credentialTrustLevel)) {
            builder.customParameter("vtr", jsonArrayOf(credentialTrustLevel.getValue()));
        }
        return builder.build();
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
    }

    private UserCredentials usingApplicableUserCredentials(MFAMethodType mfaMethodType) {
        UserCredentials applicableUserCredentials =
                mfaMethodType.equals(SMS) ? userCredentials : userCredentialsAuthApp;
        when(authenticationService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn(applicableUserCredentials);
        return applicableUserCredentials;
    }

    private UserCredentials usingApplicableUserCredentialsWithLogin(
            MFAMethodType mfaMethodType, boolean loginSuccessful) {
        UserCredentials applicableUserCredentials = usingApplicableUserCredentials(mfaMethodType);
        when(authenticationService.login(applicableUserCredentials, CommonTestVariables.PASSWORD))
                .thenReturn(loginSuccessful);
        return applicableUserCredentials;
    }

    private UserProfile generateUserProfile(String legacySubjectId) {
        return new UserProfile()
                .withEmail(EMAIL)
                .withEmailVerified(true)
                .withPhoneNumber(CommonTestVariables.UK_MOBILE_NUMBER)
                .withPhoneNumberVerified(true)
                .withPublicSubjectID(new Subject().getValue())
                .withSubjectID(INTERNAL_SUBJECT_ID.getValue())
                .withLegacySubjectID(legacySubjectId)
                .withTermsAndConditions(
                        new TermsAndConditions("1.0", NowHelper.now().toInstant().toString()));
    }

    private ClientRegistry generateClientRegistry() {
        return new ClientRegistry()
                .withClientID(CLIENT_ID.getValue())
                .withClientName(CLIENT_NAME)
                .withSectorIdentifierUri("https://test.com")
                .withSubjectType("public");
    }

    private void usingDefaultVectorOfTrust() {
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArrayOf("Cl.Cm")));
        when(clientSession.getEffectiveVectorOfTrust()).thenReturn(vectorOfTrust);
    }

    private APIGatewayProxyRequestEvent eventWithHeadersAndBody(
            Map<String, String> headers, String body) {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp(IP_ADDRESS));
        event.setHeaders(headers);
        event.setBody(body);
        return event;
    }
}
