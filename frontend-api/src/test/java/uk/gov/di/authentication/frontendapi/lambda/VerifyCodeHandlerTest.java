package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.VALID_HEADERS_WITHOUT_AUDIT_ENCODED;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_CHANGE_HOW_GET_SECURITY_CODES;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class VerifyCodeHandlerTest {

    private static final String CODE = "123456";
    private static final String INVALID_CODE = "6543221";
    private static final String CLIENT_ID = "client-id";
    private static final String CLIENT_NAME = "client-name";
    private static final String TEST_CLIENT_ID = "test-client-id";
    private static final String TEST_CLIENT_CODE = "654321";
    private static final String TEST_CLIENT_EMAIL =
            "testclient.user1@digital.cabinet-office.gov.uk";
    private static final String SECTOR_HOST = "test.account.gov.uk";
    private static final byte[] SALT = SaltHelper.generateNewSalt();
    private static final String TEST_SUBJECT_ID = "test-subject-id";
    private static final long CODE_EXPIRY_TIME = 900;
    private static final long LOCKOUT_DURATION = 799;
    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");

    private final Context context = mock(Context.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final UserProfile userProfile = mock(UserProfile.class);
    private final String expectedCommonSubject =
            ClientSubjectHelper.calculatePairwiseIdentifier(TEST_SUBJECT_ID, SECTOR_HOST, SALT);
    private final Session session =
            new Session(SESSION_ID)
                    .setEmailAddress(EMAIL)
                    .setInternalCommonSubjectIdentifier(expectedCommonSubject);
    private final Session testSession =
            new Session("test-client-session-id").setEmailAddress(TEST_CLIENT_EMAIL);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ClientSession clientSession = mock(ClientSession.class);
    private final AuditService auditService = mock(AuditService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final DynamoAccountModifiersService accountModifiersService =
            mock(DynamoAccountModifiersService.class);

    private final ClientRegistry clientRegistry =
            new ClientRegistry()
                    .withTestClient(false)
                    .withClientID(CLIENT_ID)
                    .withClientName(CLIENT_NAME);
    private final ClientRegistry testClientRegistry =
            new ClientRegistry()
                    .withTestClient(true)
                    .withClientID(TEST_CLIENT_ID)
                    .withTestClientEmailAllowlist(
                            List.of(
                                    "testclient.user1@digital.cabinet-office.gov.uk",
                                    "^(.+)@digital.cabinet-office.gov.uk$",
                                    "testclient.user2@internet.com"));

    private final AuditContext AUDIT_CONTEXT =
            new AuditContext(
                    CLIENT_ID,
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    expectedCommonSubject,
                    EMAIL,
                    IP_ADDRESS,
                    AuditService.UNKNOWN,
                    DI_PERSISTENT_SESSION_ID,
                    Optional.of(ENCODED_DEVICE_DETAILS));

    private final AuditContext AUDIT_CONTEXT_FOR_TEST_CLIENT =
            AUDIT_CONTEXT.withSessionId(testSession.getSessionId()).withClientId(TEST_CLIENT_ID);

    private VerifyCodeHandler handler;

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(VerifyCodeHandler.class);

    @AfterEach
    void tearDown() {
        assertThat(
                logging.events(),
                not(
                        hasItem(
                                withMessageContaining(
                                        CLIENT_ID,
                                        TEST_CLIENT_CODE,
                                        SESSION_ID,
                                        testSession.getSessionId()))));
    }

    @BeforeEach
    void setup() {
        handler =
                new VerifyCodeHandler(
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        codeStorageService,
                        auditService,
                        cloudwatchMetricsService,
                        accountModifiersService);

        when(authenticationService.getUserProfileFromEmail(EMAIL))
                .thenReturn(Optional.of(userProfile));

        when(authenticationService.getUserProfileFromEmail(TEST_CLIENT_EMAIL))
                .thenReturn(Optional.of(userProfile));

        when(configurationService.getDefaultOtpCodeExpiry()).thenReturn(CODE_EXPIRY_TIME);

        when(userProfile.getSubjectID()).thenReturn(TEST_SUBJECT_ID);

        when(configurationService.getEnvironment()).thenReturn("unit-test");
    }

    @Test
    void shouldReturn400IfRequestIsMissingNotificationType() {
        var body = format("{ \"code\": \"%s\"}", CODE);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        when(sessionService.getSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(session));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
        verifyNoInteractions(accountModifiersService);
    }

    @Test
    void shouldReturn400IfSessionIdIsInvalid() {
        String body =
                format("{ \"code\": \"%s\", \"notificationType\": \"%s\"  }", CODE, VERIFY_EMAIL);
        APIGatewayProxyResponseEvent result = makeCallWithCode(body, Optional.empty(), CLIENT_ID);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1000));
        verifyNoInteractions(accountModifiersService);
    }

    @Test
    void shouldReturn400IfNotificationTypeIsNotValid() {
        APIGatewayProxyResponseEvent result = makeCallWithCode(CODE, "VERIFY_TEXT");

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
        verifyNoInteractions(accountModifiersService);
    }

    private static Stream<NotificationType> emailNotificationTypes() {
        return Stream.of(VERIFY_EMAIL, VERIFY_CHANGE_HOW_GET_SECURITY_CODES);
    }

    @ParameterizedTest
    @MethodSource("emailNotificationTypes")
    void shouldReturn204ForValidEmailCodeRequest(NotificationType emailNotificationType) {
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(codeStorageService.getOtpCode(EMAIL, emailNotificationType))
                .thenReturn(Optional.of(CODE));
        APIGatewayProxyResponseEvent result =
                makeCallWithCode(CODE, emailNotificationType.toString());

        assertThat(result, hasStatus(204));
        verify(codeStorageService).deleteOtpCode(EMAIL, emailNotificationType);
        verify(sessionService).save(session);
        verifyNoInteractions(accountModifiersService);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_VERIFIED,
                        AUDIT_CONTEXT,
                        pair("notification-type", emailNotificationType.name()),
                        pair(
                                "account-recovery",
                                emailNotificationType.equals(VERIFY_CHANGE_HOW_GET_SECURITY_CODES)),
                        pair(
                                "journey-type",
                                emailNotificationType.equals(VERIFY_CHANGE_HOW_GET_SECURITY_CODES)
                                        ? "ACCOUNT_RECOVERY"
                                        : "REGISTRATION"));
    }

    @ParameterizedTest
    @MethodSource("emailNotificationTypes")
    void checkAuditEventStillEmittedWhenTICFHeaderNotProvided(
            NotificationType emailNotificationType) {
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(codeStorageService.getOtpCode(EMAIL, emailNotificationType))
                .thenReturn(Optional.of(CODE));

        String body =
                format(
                        "{ \"code\": \"%s\", \"notificationType\": \"%s\"  }",
                        CODE, emailNotificationType.toString());
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS_WITHOUT_AUDIT_ENCODED, body);
        when(sessionService.getSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(session));
        when(clientSessionService.getClientSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(clientSession));
        when(clientSession.getAuthRequestParams())
                .thenReturn(withAuthenticationRequest(CLIENT_ID).toParameters());
        when(clientService.getClient(CLIENT_ID)).thenReturn(Optional.of(clientRegistry));
        when(clientService.getClient(TEST_CLIENT_ID)).thenReturn(Optional.of(testClientRegistry));
        when(clientSessionService.getClientSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(clientSession));
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(clientSession));
        when(clientSession.getEffectiveVectorOfTrust()).thenReturn(VectorOfTrust.getDefaults());

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_VERIFIED,
                        AUDIT_CONTEXT.withTxmaAuditEncoded(Optional.empty()),
                        pair("notification-type", emailNotificationType.name()),
                        pair(
                                "account-recovery",
                                emailNotificationType.equals(VERIFY_CHANGE_HOW_GET_SECURITY_CODES)),
                        pair(
                                "journey-type",
                                emailNotificationType.equals(VERIFY_CHANGE_HOW_GET_SECURITY_CODES)
                                        ? "ACCOUNT_RECOVERY"
                                        : "REGISTRATION"));
    }

    @ParameterizedTest
    @MethodSource("emailNotificationTypes")
    void shouldReturnEmailCodeNotValidStateIfRequestCodeDoesNotMatchStoredCode(
            NotificationType emailNotificationType) {
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(codeStorageService.getOtpCode(EMAIL, emailNotificationType))
                .thenReturn(Optional.of(CODE));

        APIGatewayProxyResponseEvent result =
                makeCallWithCode(INVALID_CODE, emailNotificationType.toString());

        String expectedJourneyType =
                switch (emailNotificationType) {
                    case VERIFY_CHANGE_HOW_GET_SECURITY_CODES -> "ACCOUNT_RECOVERY";
                    case VERIFY_EMAIL -> "REGISTRATION";
                    default -> null;
                };

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1036));
        verifyNoInteractions(accountModifiersService);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.INVALID_CODE_SENT,
                        AUDIT_CONTEXT,
                        pair("notification-type", emailNotificationType.name()),
                        pair(
                                "account-recovery",
                                emailNotificationType.equals(VERIFY_CHANGE_HOW_GET_SECURITY_CODES)),
                        pair("journey-type", expectedJourneyType));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "testclient.user1@digital.cabinet-office.gov.uk",
                "abc@digital.cabinet-office.gov.uk",
                "abc.def@digital.cabinet-office.gov.uk",
                "testclient.user2@internet.com",
            })
    void shouldReturn204ForValidVerifyEmailRequestUsingTestClient(String email) {
        when(configurationService.isTestClientsEnabled()).thenReturn(true);
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(configurationService.getTestClientVerifyEmailOTP())
                .thenReturn(Optional.of(TEST_CLIENT_CODE));
        when(codeStorageService.getOtpCode(email, VERIFY_EMAIL)).thenReturn(Optional.of(CODE));
        testSession.setEmailAddress(email);
        testSession.setInternalCommonSubjectIdentifier(expectedCommonSubject);
        String body =
                format(
                        "{ \"code\": \"%s\", \"notificationType\": \"%s\"  }",
                        TEST_CLIENT_CODE, VERIFY_EMAIL);
        var result = makeCallWithCode(body, Optional.of(testSession), TEST_CLIENT_ID);

        assertThat(result, hasStatus(204));
        verifyNoInteractions(accountModifiersService);
        verify(codeStorageService).deleteOtpCode(email, VERIFY_EMAIL);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_VERIFIED,
                        AUDIT_CONTEXT_FOR_TEST_CLIENT.withEmail(email),
                        pair("notification-type", VERIFY_EMAIL.name()),
                        pair("account-recovery", false),
                        pair("journey-type", "REGISTRATION"));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "testclient.user1@digital1.cabinet-office.gov.uk",
                "abc@digital1.cabinet-office.gov.uk",
                "abc.def@digital1.cabinet-office.gov.uk",
                "testclient.user3@internet.com",
            })
    void
            shouldReturn200AndUseDefaultCodeForVerifyEmailRequestUsingTestClientWhenEmailDoesNotMatchAllowlist(
                    String email) {
        when(configurationService.isTestClientsEnabled()).thenReturn(true);
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(configurationService.getTestClientVerifyEmailOTP())
                .thenReturn(Optional.of(TEST_CLIENT_CODE));
        when(codeStorageService.getOtpCode(email, VERIFY_EMAIL)).thenReturn(Optional.of(CODE));
        testSession.setEmailAddress(email);
        testSession.setInternalCommonSubjectIdentifier(expectedCommonSubject);
        String body =
                format("{ \"code\": \"%s\", \"notificationType\": \"%s\"  }", CODE, VERIFY_EMAIL);
        var result = makeCallWithCode(body, Optional.of(testSession), TEST_CLIENT_ID);

        assertThat(result, hasStatus(204));
        verifyNoInteractions(accountModifiersService);
        verify(codeStorageService).deleteOtpCode(email, VERIFY_EMAIL);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_VERIFIED,
                        AUDIT_CONTEXT_FOR_TEST_CLIENT.withEmail(email),
                        pair("notification-type", VERIFY_EMAIL.name()),
                        pair("account-recovery", false),
                        pair("journey-type", "REGISTRATION"));
    }

    @Test
    void
            shouldReturnMaxReachedAndNotSetBlockWhenRegistrationEmailCodeAttemptsExceedMaxRetryCount() {
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(codeStorageService.getIncorrectMfaCodeAttemptsCount(EMAIL)).thenReturn(6);
        when(codeStorageService.getOtpCode(EMAIL, VERIFY_EMAIL)).thenReturn(Optional.of(CODE));
        var result = makeCallWithCode(INVALID_CODE, VERIFY_EMAIL.name());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1033));
        assertThat(session.getRetryCount(), equalTo(0));
        verifyNoInteractions(accountModifiersService);
        verify(codeStorageService).deleteIncorrectMfaCodeAttemptsCount(EMAIL);
        verify(codeStorageService, never())
                .saveBlockedForEmail(EMAIL, CODE_BLOCKED_KEY_PREFIX, LOCKOUT_DURATION);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_MAX_RETRIES_REACHED,
                        AUDIT_CONTEXT,
                        pair("notification-type", VERIFY_EMAIL.name()),
                        pair("account-recovery", false),
                        pair("journey-type", "REGISTRATION"));
    }

    @Test
    void shouldReturnMaxReachedAndNotSetBlockWhenAccountRecoveryEmailCodeIsBlocked() {
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + CodeRequestType.EMAIL_ACCOUNT_RECOVERY;
        when(codeStorageService.isBlockedForEmail(EMAIL, codeBlockedKeyPrefix)).thenReturn(true);

        var result = makeCallWithCode(CODE, VERIFY_CHANGE_HOW_GET_SECURITY_CODES.name());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1048));
        verifyNoInteractions(accountModifiersService);
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturnMaxReachedAndNotSetBlockWhenPasswordResetEmailCodeIsBlocked() {
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + CodeRequestType.EMAIL_PASSWORD_RESET;
        when(codeStorageService.isBlockedForEmail(EMAIL, codeBlockedKeyPrefix)).thenReturn(true);

        var result = makeCallWithCode(CODE, RESET_PASSWORD_WITH_CODE.name());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1039));
        verifyNoInteractions(accountModifiersService);
        verifyNoInteractions(auditService);
    }

    @ParameterizedTest
    @MethodSource("codeRequestTypes")
    void shouldReturnMaxReachedAndNotSetBlockWhenSignInCodeIsBlocked(
            CodeRequestType codeRequestType, JourneyType journeyType) {
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;
        when(codeStorageService.isBlockedForEmail(EMAIL, codeBlockedKeyPrefix)).thenReturn(true);

        var result = makeCallWithCode(CODE, MFA_SMS.name(), journeyType);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1027));
        verifyNoInteractions(accountModifiersService);
        verifyNoInteractions(auditService);
    }

    @Test
    void
            shouldReturnMaxReachedAndSetBlockWhenAccountRecoveryEmailCodeAttemptsExceedMaxRetryCount() {
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(configurationService.getLockoutDuration()).thenReturn(LOCKOUT_DURATION);

        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + CodeRequestType.EMAIL_ACCOUNT_RECOVERY;
        when(codeStorageService.isBlockedForEmail(EMAIL, codeBlockedKeyPrefix)).thenReturn(false);
        when(codeStorageService.getIncorrectMfaCodeAttemptsCount(EMAIL)).thenReturn(6);

        var result = makeCallWithCode(CODE, VERIFY_CHANGE_HOW_GET_SECURITY_CODES.name());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1048));
        verify(codeStorageService)
                .saveBlockedForEmail(EMAIL, codeBlockedKeyPrefix, LOCKOUT_DURATION);
        verify(codeStorageService).deleteIncorrectMfaCodeAttemptsCount(EMAIL);
        verifyNoInteractions(accountModifiersService);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_MAX_RETRIES_REACHED,
                        AUDIT_CONTEXT,
                        pair("notification-type", VERIFY_CHANGE_HOW_GET_SECURITY_CODES.name()),
                        pair("account-recovery", true),
                        pair("journey-type", "ACCOUNT_RECOVERY"));
    }

    @ParameterizedTest
    @MethodSource("codeRequestTypes")
    void shouldReturn204ForValidMfaSmsRequestAndRemoveAccountRecoveryBlockWhenPresent(
            CodeRequestType codeRequestType, JourneyType journeyType) {
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(codeStorageService.getOtpCode(EMAIL, MFA_SMS)).thenReturn(Optional.of(CODE));
        when(accountModifiersService.isAccountRecoveryBlockPresent(anyString())).thenReturn(true);
        session.setNewAccount(Session.AccountState.EXISTING);

        when(configurationService.getInternalSectorUri()).thenReturn("http://" + SECTOR_HOST);
        when(authenticationService.getOrGenerateSalt(userProfile)).thenReturn(SALT);

        var result = makeCallWithCode(CODE, MFA_SMS.toString(), journeyType);

        assertThat(result, hasStatus(204));
        assertThat(session.getVerifiedMfaMethodType(), equalTo(MFAMethodType.SMS));
        verify(codeStorageService).deleteOtpCode(EMAIL, MFA_SMS);
        verify(accountModifiersService).removeAccountRecoveryBlockIfPresent(expectedCommonSubject);
        var saveSessionCount = journeyType == JourneyType.PASSWORD_RESET_MFA ? 3 : 2;
        verify(sessionService, times(saveSessionCount)).save(session);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_VERIFIED,
                        AUDIT_CONTEXT,
                        pair("notification-type", MFA_SMS.name()),
                        pair("account-recovery", false),
                        pair(
                                "journey-type",
                                journeyType != null ? String.valueOf(journeyType) : "SIGN_IN"),
                        pair("mfa-type", MFAMethodType.SMS.getValue()),
                        pair("loginFailureCount", 0),
                        pair("MFACodeEntered", "123456"));
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.ACCOUNT_RECOVERY_BLOCK_REMOVED,
                        AUDIT_CONTEXT,
                        pair("mfa-type", MFAMethodType.SMS.getValue()));
        verify(cloudwatchMetricsService)
                .incrementAuthenticationSuccess(
                        Session.AccountState.EXISTING, CLIENT_ID, CLIENT_NAME, "P0", false, true);
    }

    @Test
    void shouldReturn204ForValidMfaSmsRequestAndNotRemoveAccountRecoveryBlockWhenNotPresent() {
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(codeStorageService.getOtpCode(EMAIL, MFA_SMS)).thenReturn(Optional.of(CODE));
        when(accountModifiersService.isAccountRecoveryBlockPresent(expectedCommonSubject))
                .thenReturn(false);
        session.setNewAccount(Session.AccountState.EXISTING);

        var result = makeCallWithCode(CODE, MFA_SMS.toString());

        assertThat(result, hasStatus(204));
        assertThat(session.getVerifiedMfaMethodType(), equalTo(MFAMethodType.SMS));
        verify(codeStorageService).deleteOtpCode(EMAIL, MFA_SMS);
        verify(accountModifiersService, never()).removeAccountRecoveryBlockIfPresent(anyString());
        verify(sessionService, times(2)).save(session);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_VERIFIED,
                        AUDIT_CONTEXT,
                        pair("notification-type", MFA_SMS.name()),
                        pair("account-recovery", false),
                        pair("journey-type", "SIGN_IN"),
                        pair("mfa-type", MFAMethodType.SMS.getValue()),
                        pair("loginFailureCount", 0),
                        pair("MFACodeEntered", "123456"));
        verify(cloudwatchMetricsService)
                .incrementAuthenticationSuccess(
                        Session.AccountState.EXISTING, CLIENT_ID, CLIENT_NAME, "P0", false, true);
    }

    @Test
    void shouldReturnMfaCodeNotValidWhenCodeIsInvalid() {
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(codeStorageService.getOtpCode(EMAIL, MFA_SMS)).thenReturn(Optional.of(CODE));

        APIGatewayProxyResponseEvent result = makeCallWithCode(INVALID_CODE, MFA_SMS.toString());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1035));
        verifyNoInteractions(accountModifiersService);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.INVALID_CODE_SENT,
                        AUDIT_CONTEXT,
                        pair("notification-type", MFA_SMS.name()),
                        pair("account-recovery", false),
                        pair("journey-type", "SIGN_IN"),
                        pair("mfa-type", MFAMethodType.SMS.getValue()),
                        pair("loginFailureCount", 0),
                        pair("MFACodeEntered", "6543221"),
                        pair("MaxSmsCount", configurationService.getCodeMaxRetries()));
    }

    @ParameterizedTest
    @MethodSource("codeRequestTypes")
    void shouldReturnMaxReachedAndSetBlockedMfaCodeAttemptsWhenSignInExceedMaxRetryCount(
            CodeRequestType codeRequestType, JourneyType journeyType) {
        when(configurationService.getCodeMaxRetries()).thenReturn(0);
        when(configurationService.getLockoutDuration()).thenReturn(LOCKOUT_DURATION);
        when(codeStorageService.getOtpCode(EMAIL, MFA_SMS)).thenReturn(Optional.of(CODE));
        when(codeStorageService.getIncorrectMfaCodeAttemptsCount(EMAIL)).thenReturn(1);

        var result = makeCallWithCode(INVALID_CODE, MFA_SMS.toString(), journeyType);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1027));
        assertThat(session.getRetryCount(), equalTo(0));
        if (codeRequestType != CodeRequestType.SMS_REAUTHENTICATION) {
            verify(codeStorageService)
                    .saveBlockedForEmail(
                            EMAIL, CODE_BLOCKED_KEY_PREFIX + codeRequestType, LOCKOUT_DURATION);
        }
        verifyNoInteractions(accountModifiersService);
        verify(codeStorageService).deleteIncorrectMfaCodeAttemptsCount(EMAIL);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_MAX_RETRIES_REACHED,
                        AUDIT_CONTEXT,
                        pair("notification-type", MFA_SMS.name()),
                        pair("account-recovery", false),
                        pair(
                                "journey-type",
                                journeyType != null ? String.valueOf(journeyType) : "SIGN_IN"),
                        pair("mfa-type", MFAMethodType.SMS.getValue()),
                        pair("loginFailureCount", 0),
                        pair("MFACodeEntered", "6543221"),
                        pair("MaxSmsCount", configurationService.getCodeMaxRetries()));
    }

    @Test
    void shouldReturnMaxReachedAndSetBlockedMfaCodeAttemptsWhenPasswordResetExceedMaxRetryCount() {
        when(configurationService.getCodeMaxRetries()).thenReturn(0);
        when(configurationService.getLockoutDuration()).thenReturn(LOCKOUT_DURATION);
        when(codeStorageService.getOtpCode(EMAIL, RESET_PASSWORD_WITH_CODE))
                .thenReturn(Optional.of(CODE));
        when(codeStorageService.getIncorrectMfaCodeAttemptsCount(EMAIL)).thenReturn(1);

        var result = makeCallWithCode(INVALID_CODE, RESET_PASSWORD_WITH_CODE.toString());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1039));
        assertThat(session.getRetryCount(), equalTo(0));
        verify(codeStorageService)
                .saveBlockedForEmail(
                        EMAIL,
                        CODE_BLOCKED_KEY_PREFIX + CodeRequestType.EMAIL_PASSWORD_RESET,
                        LOCKOUT_DURATION);
        verifyNoInteractions(accountModifiersService);
        verify(codeStorageService).deleteIncorrectMfaCodeAttemptsCount(EMAIL);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_MAX_RETRIES_REACHED,
                        AUDIT_CONTEXT,
                        pair("notification-type", RESET_PASSWORD_WITH_CODE.name()),
                        pair("account-recovery", false),
                        pair("journey-type", "PASSWORD_RESET"));
    }

    @Test
    void shouldReturn204ForValidResetPasswordRequestUsingTestClient() {
        when(configurationService.isTestClientsEnabled()).thenReturn(true);
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(configurationService.getTestClientVerifyEmailOTP())
                .thenReturn(Optional.of(TEST_CLIENT_CODE));
        when(codeStorageService.getOtpCode(TEST_CLIENT_EMAIL, RESET_PASSWORD_WITH_CODE))
                .thenReturn(Optional.of(CODE));
        String body =
                format(
                        "{ \"code\": \"%s\", \"notificationType\": \"%s\"  }",
                        TEST_CLIENT_CODE, RESET_PASSWORD_WITH_CODE);
        APIGatewayProxyResponseEvent result =
                makeCallWithCode(body, Optional.of(testSession), TEST_CLIENT_ID);

        verifyNoInteractions(accountModifiersService);
        verify(codeStorageService).deleteOtpCode(TEST_CLIENT_EMAIL, RESET_PASSWORD_WITH_CODE);
        assertThat(result, hasStatus(204));
    }

    private APIGatewayProxyResponseEvent makeCallWithCode(String code, String notificationType) {
        String body =
                format(
                        "{ \"code\": \"%s\", \"notificationType\": \"%s\"  }",
                        code, notificationType);
        return makeCallWithCode(body, Optional.of(session), CLIENT_ID);
    }

    private APIGatewayProxyResponseEvent makeCallWithCode(
            String code, String notificationType, JourneyType journeyType) {
        if (journeyType == null) {
            return makeCallWithCode(code, notificationType);
        }
        String body =
                format(
                        "{ \"code\": \"%s\", \"notificationType\": \"%s\", \"journeyType\":\"%s\" }",
                        code, notificationType, journeyType.getValue());
        return makeCallWithCode(body, Optional.of(session), CLIENT_ID);
    }

    private APIGatewayProxyResponseEvent makeCallWithCode(
            String body, Optional<Session> session, String clientId) {
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        when(sessionService.getSessionFromRequestHeaders(event.getHeaders())).thenReturn(session);
        when(clientSessionService.getClientSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(clientSession));
        when(clientSession.getAuthRequestParams())
                .thenReturn(withAuthenticationRequest(clientId).toParameters());
        when(clientService.getClient(CLIENT_ID)).thenReturn(Optional.of(clientRegistry));
        when(clientService.getClient(TEST_CLIENT_ID)).thenReturn(Optional.of(testClientRegistry));
        when(clientSessionService.getClientSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(clientSession));
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(clientSession));
        when(clientSession.getEffectiveVectorOfTrust()).thenReturn(VectorOfTrust.getDefaults());

        return handler.handleRequest(event, context);
    }

    private AuthenticationRequest withAuthenticationRequest(String clientId) {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        return new AuthenticationRequest.Builder(
                        new ResponseType(ResponseType.Value.CODE),
                        scope,
                        new ClientID(clientId),
                        REDIRECT_URI)
                .state(new State())
                .nonce(new Nonce())
                .build();
    }

    private static Stream<Arguments> codeRequestTypes() {
        return Stream.of(
                Arguments.of(CodeRequestType.PW_RESET_MFA_SMS, JourneyType.PASSWORD_RESET_MFA),
                Arguments.of(CodeRequestType.SMS_REAUTHENTICATION, JourneyType.REAUTHENTICATION),
                Arguments.of(CodeRequestType.SMS_SIGN_IN, JourneyType.SIGN_IN),
                Arguments.of(CodeRequestType.SMS_SIGN_IN, null));
    }
}
