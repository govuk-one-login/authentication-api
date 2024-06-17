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
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.MfaRequest;
import uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.UK_MOBILE_NUMBER;
import static uk.gov.di.authentication.frontendapi.lambda.StartHandlerTest.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.lambda.StartHandlerTest.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.lambda.BaseFrontendHandler.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class MfaHandlerTest {

    private MfaHandler handler;
    private static final String CODE = "123456";
    private static final long CODE_EXPIRY_TIME = 900;
    private static final long LOCKOUT_DURATION = 799;
    private static final String TEST_CLIENT_ID = "test-client-id";
    public static final String ENCODED_DEVICE_DETAILS =
            "YTtKVSlub1YlOSBTeEI4J3pVLVd7Jjl8VkBfREs2N3clZmN+fnU7fXNbcTJjKyEzN2IuUXIgMGttV058fGhUZ0xhenZUdldEblB8SH18XypwXUhWPXhYXTNQeURW%";

    private final String expectedCommonSubject =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    new Subject().getValue(), "test.account.gov.uk", SaltHelper.generateNewSalt());
    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private final Context context = mock(Context.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final CodeGeneratorService codeGeneratorService = mock(CodeGeneratorService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final ClientSession clientSession = mock(ClientSession.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private static final Json objectMapper = SerializationService.getInstance();
    private final Session session =
            new Session("a-session-id")
                    .setEmailAddress(EMAIL)
                    .setInternalCommonSubjectIdentifier(expectedCommonSubject);
    private static final String persistentId = "some-persistent-id-value";
    private final Map<String, String> validHeaders =
            Map.ofEntries(
                    Map.entry(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, persistentId),
                    Map.entry("Session-Id", session.getSessionId()),
                    Map.entry(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID),
                    Map.entry(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS));
    private final ClientRegistry testClientRegistry =
            new ClientRegistry()
                    .withTestClient(true)
                    .withClientID(TEST_CLIENT_ID)
                    .withTestClientEmailAllowlist(
                            List.of(
                                    "joe.bloggs@digital.cabinet-office.gov.uk",
                                    EMAIL,
                                    "jb2@digital.cabinet-office.gov.uk"));

    @RegisterExtension
    private final CaptureLoggingExtension logging = new CaptureLoggingExtension(MfaHandler.class);

    @AfterEach
    void tearDown() {
        assertThat(
                logging.events(),
                not(hasItem(withMessageContaining(session.getSessionId(), TEST_CLIENT_ID))));
    }

    @BeforeEach
    void setUp() {
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(configurationService.getDefaultOtpCodeExpiry()).thenReturn(CODE_EXPIRY_TIME);
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        handler =
                new MfaHandler(
                        configurationService,
                        sessionService,
                        codeGeneratorService,
                        codeStorageService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        auditService,
                        sqsClient);
        when(clientService.getClient(TEST_CLIENT_ID)).thenReturn(Optional.of(testClientRegistry));
    }

    @Test
    void shouldReturn204ForSuccessfulMfaRequestWhenNonResendCode() throws Json.JsonException {
        usingValidSession();

        when(authenticationService.getPhoneNumber(EMAIL))
                .thenReturn(Optional.of(CommonTestVariables.UK_MOBILE_NUMBER));
        when(codeGeneratorService.sixDigitCode()).thenReturn(CODE);
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        CommonTestVariables.UK_MOBILE_NUMBER, MFA_SMS, CODE, SupportedLanguage.EN);
        var body = format("{ \"email\": \"%s\"}", EMAIL);
        var event = apiRequestEventWithHeadersAndBody(validHeaders, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(sqsClient).send(objectMapper.writeValueAsString(notifyRequest));
        verify(codeStorageService).saveOtpCode(EMAIL, CODE, CODE_EXPIRY_TIME, MFA_SMS);
        assertThat(result, hasStatus(204));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.MFA_CODE_SENT,
                        "",
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        expectedCommonSubject,
                        EMAIL,
                        IP_ADDRESS,
                        CommonTestVariables.UK_MOBILE_NUMBER,
                        persistentId,
                        new AuditService.RestrictedSection(Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("journey-type", JourneyType.SIGN_IN),
                        pair("mfa-type", NotificationType.MFA_SMS.getMfaMethodType().getValue()));
    }

    @Test
    void checkAuditEventStillEmittedWhenTICFHeaderNotProvided() {
        usingValidSession();

        var headers = new HashMap<String, String>();
        headers.putAll(validHeaders);
        headers.remove(TXMA_AUDIT_ENCODED_HEADER);

        when(authenticationService.getPhoneNumber(EMAIL)).thenReturn(Optional.of(UK_MOBILE_NUMBER));
        when(codeGeneratorService.sixDigitCode()).thenReturn(CODE);
        var body = format("{ \"email\": \"%s\"}", EMAIL);
        var event = apiRequestEventWithHeadersAndBody(headers, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.MFA_CODE_SENT,
                        "",
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        expectedCommonSubject,
                        EMAIL,
                        IP_ADDRESS,
                        UK_MOBILE_NUMBER,
                        persistentId,
                        AuditService.RestrictedSection.empty,
                        pair("journey-type", JourneyType.SIGN_IN),
                        pair("mfa-type", NotificationType.MFA_SMS.getMfaMethodType().getValue()));
    }

    @Test
    void shouldReturn204ForSuccessfulMfaRequestWhenResendingCode() throws Json.JsonException {
        usingValidSession();

        when(authenticationService.getPhoneNumber(EMAIL))
                .thenReturn(Optional.of(CommonTestVariables.UK_MOBILE_NUMBER));
        when(codeStorageService.getOtpCode(EMAIL, VERIFY_PHONE_NUMBER))
                .thenReturn(Optional.of(CODE));
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        CommonTestVariables.UK_MOBILE_NUMBER,
                        VERIFY_PHONE_NUMBER,
                        CODE,
                        SupportedLanguage.EN);
        var body = format("{ \"email\": \"%s\", \"isResendCodeRequest\": \"%s\"}", EMAIL, "true");
        var event = apiRequestEventWithHeadersAndBody(validHeaders, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(sqsClient).send(objectMapper.writeValueAsString(notifyRequest));
        verify(codeGeneratorService, never()).sixDigitCode();
        verify(codeStorageService, never())
                .saveOtpCode(
                        any(String.class),
                        any(String.class),
                        anyLong(),
                        any(NotificationType.class));
        assertThat(result, hasStatus(204));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.MFA_CODE_SENT,
                        "",
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        expectedCommonSubject,
                        EMAIL,
                        IP_ADDRESS,
                        CommonTestVariables.UK_MOBILE_NUMBER,
                        persistentId,
                        new AuditService.RestrictedSection(Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("journey-type", JourneyType.SIGN_IN),
                        pair("mfa-type", NotificationType.MFA_SMS.getMfaMethodType().getValue()));
    }

    @Test
    void shouldReturn204AndAllowMfaRequestDuringUplift() throws Json.JsonException {
        usingValidSession();

        when(authenticationService.getPhoneNumber(EMAIL))
                .thenReturn(Optional.of(CommonTestVariables.UK_MOBILE_NUMBER));
        when(codeGeneratorService.sixDigitCode()).thenReturn(CODE);
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        CommonTestVariables.UK_MOBILE_NUMBER, MFA_SMS, CODE, SupportedLanguage.EN);
        var body = format("{ \"email\": \"%s\"}", EMAIL);
        var event = apiRequestEventWithHeadersAndBody(validHeaders, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(sqsClient).send(objectMapper.writeValueAsString(notifyRequest));
        verify(codeStorageService).saveOtpCode(EMAIL, CODE, CODE_EXPIRY_TIME, MFA_SMS);
        assertThat(result, hasStatus(204));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.MFA_CODE_SENT,
                        "",
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        expectedCommonSubject,
                        EMAIL,
                        IP_ADDRESS,
                        CommonTestVariables.UK_MOBILE_NUMBER,
                        persistentId,
                        new AuditService.RestrictedSection(Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("journey-type", JourneyType.SIGN_IN),
                        pair("mfa-type", NotificationType.MFA_SMS.getMfaMethodType().getValue()));
    }

    @Test
    void shouldReturn400WhenInvalidMFAJourneyCombination() throws Json.JsonException {
        usingValidSession();

        when(authenticationService.getPhoneNumber(EMAIL))
                .thenReturn(Optional.of(CommonTestVariables.UK_MOBILE_NUMBER));
        when(codeGeneratorService.sixDigitCode()).thenReturn(CODE);
        var body = format("{ \"email\": \"%s\"}", EMAIL);
        var event = apiRequestEventWithHeadersAndBody(validHeaders, body);

        MfaRequest test = new MfaRequest(EMAIL, false, JourneyType.PASSWORD_RESET);
        APIGatewayProxyResponseEvent result =
                handler.handleRequestWithUserContext(
                        event, context, test, UserContext.builder(session).build());

        assertThat(result, hasStatus(400));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400WhenSessionIdIsInvalid() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"email\": \"%s\"}", EMAIL));
        event.setRequestContext(contextWithSourceIp(IP_ADDRESS));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400WhenEmailInSessionDoesNotMatchEmailInRequest() {
        usingValidSession();
        when(authenticationService.getPhoneNumber(EMAIL))
                .thenReturn(Optional.of(CommonTestVariables.UK_MOBILE_NUMBER));
        when(codeGeneratorService.sixDigitCode()).thenReturn(CODE);
        var body = format("{ \"email\": \"%s\"}", "wrong.email@gov.uk");
        var event = apiRequestEventWithHeadersAndBody(validHeaders, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.MFA_MISMATCHED_EMAIL,
                        "",
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        expectedCommonSubject,
                        "wrong.email@gov.uk",
                        IP_ADDRESS,
                        AuditService.UNKNOWN,
                        persistentId,
                        new AuditService.RestrictedSection(Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("journey-type", JourneyType.SIGN_IN),
                        pair("mfa-type", NotificationType.MFA_SMS.getMfaMethodType().getValue()));
    }

    @Test
    void shouldReturnErrorResponseWhenUsersPhoneNumberIsNotStored() {
        usingValidSession();
        when(authenticationService.getPhoneNumber(EMAIL)).thenReturn(Optional.empty());
        var body = format("{ \"email\": \"%s\"}", EMAIL);
        var event = apiRequestEventWithHeadersAndBody(validHeaders, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1014));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.MFA_MISSING_PHONE_NUMBER,
                        "",
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        expectedCommonSubject,
                        EMAIL,
                        IP_ADDRESS,
                        AuditService.UNKNOWN,
                        persistentId,
                        new AuditService.RestrictedSection(Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("journey-type", JourneyType.SIGN_IN),
                        pair("mfa-type", NotificationType.MFA_SMS.getMfaMethodType()));
    }

    @Test
    void
            shouldReturn204IfUserHasReachedTheOtpRequestLimitsInADifferentLambdaButNotSmsSignInOtpRequestLimit() {
        when(authenticationService.getPhoneNumber(EMAIL))
                .thenReturn(Optional.of(CommonTestVariables.UK_MOBILE_NUMBER));

        usingValidSession();
        when(configurationService.getLockoutDuration()).thenReturn(LOCKOUT_DURATION);
        session.incrementCodeRequestCount(NotificationType.VERIFY_EMAIL, JourneyType.REGISTRATION);
        session.incrementCodeRequestCount(NotificationType.VERIFY_EMAIL, JourneyType.REGISTRATION);
        session.incrementCodeRequestCount(NotificationType.VERIFY_EMAIL, JourneyType.REGISTRATION);
        session.incrementCodeRequestCount(NotificationType.VERIFY_EMAIL, JourneyType.REGISTRATION);
        session.incrementCodeRequestCount(NotificationType.VERIFY_EMAIL, JourneyType.REGISTRATION);

        var body = format("{ \"email\": \"%s\"}", EMAIL);
        var event = apiRequestEventWithHeadersAndBody(validHeaders, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(204, result.getStatusCode());
    }

    @Test
    void shouldReturn204IfUserIsBlockedForRequestingADifferentOtpTypeThanSmsSignInOtpRequest() {
        when(authenticationService.getPhoneNumber(EMAIL))
                .thenReturn(Optional.of(CommonTestVariables.UK_MOBILE_NUMBER));

        usingValidSession();

        when(configurationService.getLockoutDuration()).thenReturn(LOCKOUT_DURATION);

        CodeRequestType codeRequestTypeForBlockedOtpRequestType =
                CodeRequestType.getCodeRequestType(
                        NotificationType.VERIFY_EMAIL, JourneyType.REGISTRATION);
        when(codeStorageService.isBlockedForEmail(
                        EMAIL,
                        CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestTypeForBlockedOtpRequestType))
                .thenReturn(true);

        var body = format("{ \"email\": \"%s\"}", EMAIL);
        var event = apiRequestEventWithHeadersAndBody(validHeaders, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(204, result.getStatusCode());
    }

    @ParameterizedTest
    @MethodSource("smsJourneyTypes")
    void shouldReturn400IfUserHasReachedTheSmsSignInCodeRequestLimit(JourneyType journeyType) {
        usingValidSession();
        when(configurationService.getLockoutDuration()).thenReturn(LOCKOUT_DURATION);
        session.incrementCodeRequestCount(MFA_SMS, journeyType);
        session.incrementCodeRequestCount(MFA_SMS, journeyType);
        session.incrementCodeRequestCount(MFA_SMS, journeyType);
        session.incrementCodeRequestCount(MFA_SMS, journeyType);
        session.incrementCodeRequestCount(MFA_SMS, journeyType);

        var body = format("{ \"email\": \"%s\", \"journeyType\": \"%s\"}", EMAIL, journeyType);
        var event = apiRequestEventWithHeadersAndBody(validHeaders, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1025));

        var codeRequestType = CodeRequestType.getCodeRequestType(MFAMethodType.SMS, journeyType);
        verify(codeStorageService)
                .saveBlockedForEmail(
                        EMAIL, CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType, LOCKOUT_DURATION);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.MFA_INVALID_CODE_REQUEST,
                        "",
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        expectedCommonSubject,
                        EMAIL,
                        IP_ADDRESS,
                        AuditService.UNKNOWN,
                        persistentId,
                        new AuditService.RestrictedSection(Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("journey-type", journeyType),
                        pair("mfa-type", MFAMethodType.SMS.getValue()));
    }

    @ParameterizedTest
    @MethodSource("smsJourneyTypes")
    void shouldReturn400IfUserIsBlockedFromRequestingAnyMoreMfaCodes(JourneyType journeyType) {
        usingValidSession();
        var codeRequestType = CodeRequestType.getCodeRequestType(MFAMethodType.SMS, journeyType);
        when(codeStorageService.isBlockedForEmail(
                        EMAIL, CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType))
                .thenReturn(true);

        var body = format("{ \"email\": \"%s\", \"journeyType\": \"%s\"}", EMAIL, journeyType);
        var event = apiRequestEventWithHeadersAndBody(validHeaders, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1026));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.MFA_INVALID_CODE_REQUEST,
                        "",
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        expectedCommonSubject,
                        EMAIL,
                        IP_ADDRESS,
                        AuditService.UNKNOWN,
                        persistentId,
                        new AuditService.RestrictedSection(Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("journey-type", journeyType),
                        pair("mfa-type", MFAMethodType.SMS.getValue()));
    }

    @ParameterizedTest
    @MethodSource("smsJourneyTypes")
    void shouldReturn400IfUserIsBlockedFromAttemptingMfaCodes(JourneyType journeyType) {
        usingValidSession();
        when(authenticationService.getPhoneNumber(EMAIL))
                .thenReturn(Optional.of(CommonTestVariables.UK_MOBILE_NUMBER));
        var codeRequestType = CodeRequestType.getCodeRequestType(MFAMethodType.SMS, journeyType);
        when(codeStorageService.isBlockedForEmail(EMAIL, CODE_BLOCKED_KEY_PREFIX + codeRequestType))
                .thenReturn(true);

        var body = format("{ \"email\": \"%s\", \"journeyType\": \"%s\"}", EMAIL, journeyType);
        var event = apiRequestEventWithHeadersAndBody(validHeaders, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1027));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.MFA_INVALID_CODE_REQUEST,
                        "",
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        expectedCommonSubject,
                        EMAIL,
                        IP_ADDRESS,
                        AuditService.UNKNOWN,
                        persistentId,
                        new AuditService.RestrictedSection(Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("journey-type", journeyType),
                        pair("mfa-type", MFAMethodType.SMS.getValue()));
    }

    @Test
    void shouldReturn204AndNotSendMessageForSuccessfulMfaRequestOnTestClient()
            throws Json.JsonException {
        usingValidSession();
        usingValidClientSession(TEST_CLIENT_ID);
        when(configurationService.isTestClientsEnabled()).thenReturn(true);
        when(authenticationService.getPhoneNumber(EMAIL))
                .thenReturn(Optional.of(CommonTestVariables.UK_MOBILE_NUMBER));
        when(codeGeneratorService.sixDigitCode()).thenReturn(CODE);
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        CommonTestVariables.UK_MOBILE_NUMBER, MFA_SMS, CODE, SupportedLanguage.EN);
        var body = format("{ \"email\": \"%s\"}", EMAIL);
        var event = apiRequestEventWithHeadersAndBody(validHeaders, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(sqsClient, never()).send(objectMapper.writeValueAsString(notifyRequest));
        verify(codeStorageService).saveOtpCode(EMAIL, CODE, CODE_EXPIRY_TIME, MFA_SMS);
        assertThat(result, hasStatus(204));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.MFA_CODE_SENT_FOR_TEST_CLIENT,
                        TEST_CLIENT_ID,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        expectedCommonSubject,
                        EMAIL,
                        IP_ADDRESS,
                        CommonTestVariables.UK_MOBILE_NUMBER,
                        persistentId,
                        new AuditService.RestrictedSection(Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("journey-type", JourneyType.SIGN_IN),
                        pair("mfa-type", NotificationType.MFA_SMS.getMfaMethodType().getValue()));
    }

    @Test
    void shouldUseExistingOtpCodeIfOneExists() throws Json.JsonException {

        usingValidSession();

        when(codeStorageService.getOtpCode(any(String.class), any(NotificationType.class)))
                .thenReturn(Optional.of(CODE));
        when(authenticationService.getPhoneNumber(EMAIL))
                .thenReturn(Optional.of(CommonTestVariables.UK_MOBILE_NUMBER));

        var body = format("{ \"email\": \"%s\"}", EMAIL);
        var event = apiRequestEventWithHeadersAndBody(validHeaders, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        NotifyRequest notifyRequest =
                new NotifyRequest(
                        CommonTestVariables.UK_MOBILE_NUMBER, MFA_SMS, CODE, SupportedLanguage.EN);
        String serialisedRequest = objectMapper.writeValueAsString(notifyRequest);

        verify(codeGeneratorService, never()).sixDigitCode();
        verify(codeStorageService, never())
                .saveOtpCode(
                        any(String.class),
                        any(String.class),
                        anyLong(),
                        any(NotificationType.class));
        verify(sqsClient).send(serialisedRequest);
        assertThat(result, hasStatus(204));
    }

    @Test
    void shouldGenerateAndSaveOtpCodeIfExistingOneNotFound() throws Json.JsonException {

        usingValidSession();

        when(codeStorageService.getOtpCode(any(String.class), any(NotificationType.class)))
                .thenReturn(Optional.empty());
        when(codeGeneratorService.sixDigitCode()).thenReturn(CODE);

        when(authenticationService.getPhoneNumber(EMAIL))
                .thenReturn(Optional.of(CommonTestVariables.UK_MOBILE_NUMBER));

        var body = format("{ \"email\": \"%s\"}", EMAIL);
        var event = apiRequestEventWithHeadersAndBody(validHeaders, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        NotifyRequest notifyRequest =
                new NotifyRequest(
                        CommonTestVariables.UK_MOBILE_NUMBER, MFA_SMS, CODE, SupportedLanguage.EN);
        String serialisedRequest = objectMapper.writeValueAsString(notifyRequest);

        verify(codeGeneratorService).sixDigitCode();
        verify(codeStorageService)
                .saveOtpCode(
                        any(String.class),
                        any(String.class),
                        anyLong(),
                        any(NotificationType.class));
        verify(sqsClient).send(serialisedRequest);
        assertThat(result, hasStatus(204));
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
    }

    private void usingValidClientSession(String clientId) {
        when(clientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(clientSession));
        when(clientSession.getAuthRequestParams())
                .thenReturn(withAuthenticationRequest(clientId).toParameters());
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

    private static Stream<Arguments> smsJourneyTypes() {
        return Stream.of(
                Arguments.of(JourneyType.PASSWORD_RESET_MFA),
                Arguments.of(JourneyType.SIGN_IN),
                Arguments.of(JourneyType.REAUTHENTICATION));
    }
}
