package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
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
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.VerifyMfaCodeRequest;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.validation.AuthAppCodeValidator;
import uk.gov.di.authentication.shared.validation.MfaCodeValidatorFactory;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class VerifyMfaCodeHandlerTest {

    private static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private static final String CODE = "123456";
    private static final String CLIENT_ID = "client-id";
    private static final String TEST_CLIENT_CODE = "654321";
    private static final String CLIENT_SESSION_ID = "client-session-id";
    private static final String SUBJECT_ID = "test-subject-id";
    private final Session session = new Session("session-id").setEmailAddress(TEST_EMAIL_ADDRESS);
    private final Json objectMapper = SerializationService.getInstance();
    public VerifyMfaCodeHandler handler;

    private final Context context = mock(Context.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final MfaCodeValidatorFactory mfaCodeValidatorFactory =
            mock(MfaCodeValidatorFactory.class);
    private final AuthAppCodeValidator authAppCodeValidator = mock(AuthAppCodeValidator.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientRegistry clientRegistry = mock(ClientRegistry.class);
    private final ClientService clientService = mock(ClientService.class);
    private final UserProfile userProfile = mock(UserProfile.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ClientSession clientSession = mock(ClientSession.class);
    private final AuditService auditService = mock(AuditService.class);

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(VerifyCodeHandler.class);

    @BeforeEach
    void setUp() {
        when(authenticationService.getUserProfileFromEmail(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(clientService.getClient(CLIENT_ID)).thenReturn(Optional.of(clientRegistry));
        when(clientRegistry.getClientID()).thenReturn(CLIENT_ID);
        when(clientSession.getAuthRequestParams())
                .thenReturn(withAuthenticationRequest().toParameters());

        when(userProfile.getSubjectID()).thenReturn(SUBJECT_ID);
        when(configurationService.getBlockedEmailDuration()).thenReturn(900L);
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        handler =
                new VerifyMfaCodeHandler(
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        codeStorageService,
                        auditService,
                        mfaCodeValidatorFactory);
    }

    @AfterEach
    void tearDown() {
        assertThat(
                logging.events(),
                not(
                        hasItem(
                                withMessageContaining(
                                        CLIENT_ID,
                                        TEST_CLIENT_CODE,
                                        session.getSessionId(),
                                        CLIENT_SESSION_ID))));
    }

    @Test
    void shouldReturn204WhenSuccessfulAuthCodeRegistrationRequest() throws Json.JsonException {
        when(mfaCodeValidatorFactory.getMfaCodeValidator(any(), anyBoolean(), any()))
                .thenReturn(Optional.of(authAppCodeValidator));
        when(authAppCodeValidator.validateCode(CODE)).thenReturn(Optional.empty());
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, VERIFY_EMAIL))
                .thenReturn(Optional.of(CODE));
        var result = makeCallWithCode(true);

        assertThat(result, hasStatus(204));
        assertThat(session.getVerifiedMfaMethodType(), equalTo(MFAMethodType.AUTH_APP));
        verify(authenticationService)
                .setMFAMethodVerifiedTrue(TEST_EMAIL_ADDRESS, MFAMethodType.AUTH_APP);
        verify(codeStorageService, never())
                .saveBlockedForEmail(TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX, 900L);
        verify(codeStorageService, never()).deleteIncorrectMfaCodeAttemptsCount(TEST_EMAIL_ADDRESS);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_VERIFIED,
                        context.getAwsRequestId(),
                        session.getSessionId(),
                        CLIENT_ID,
                        SUBJECT_ID,
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE,
                        pair("mfa-type", MFAMethodType.AUTH_APP.getValue()));
    }

    @Test
    void shouldReturn204WhenSuccessfulAuthCodeLoginRequest() throws Json.JsonException {
        when(mfaCodeValidatorFactory.getMfaCodeValidator(any(), anyBoolean(), any()))
                .thenReturn(Optional.of(authAppCodeValidator));
        when(authAppCodeValidator.validateCode(CODE)).thenReturn(Optional.empty());
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, VERIFY_EMAIL))
                .thenReturn(Optional.of(CODE));
        var result = makeCallWithCode(false);

        assertThat(result, hasStatus(204));
        assertThat(session.getVerifiedMfaMethodType(), equalTo(MFAMethodType.AUTH_APP));
        verify(authenticationService, never())
                .setMFAMethodVerifiedTrue(TEST_EMAIL_ADDRESS, MFAMethodType.AUTH_APP);
        verify(codeStorageService, never())
                .saveBlockedForEmail(TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX, 900L);
        verify(codeStorageService, never()).deleteIncorrectMfaCodeAttemptsCount(TEST_EMAIL_ADDRESS);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_VERIFIED,
                        context.getAwsRequestId(),
                        session.getSessionId(),
                        CLIENT_ID,
                        SUBJECT_ID,
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE,
                        pair("mfa-type", MFAMethodType.AUTH_APP.getValue()));
    }

    @Test
    void shouldReturn400IfMfaCodeValidatorCannotBeFound() throws Json.JsonException {
        when(mfaCodeValidatorFactory.getMfaCodeValidator(any(), anyBoolean(), any()))
                .thenReturn(Optional.empty());
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, VERIFY_EMAIL))
                .thenReturn(Optional.of(CODE));
        var result = makeCallWithCode(true);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1002));
        assertThat(session.getVerifiedMfaMethodType(), equalTo(null));
        verify(authenticationService, never())
                .setMFAMethodVerifiedTrue(TEST_EMAIL_ADDRESS, MFAMethodType.AUTH_APP);
        verifyNoInteractions(auditService);
        verifyNoInteractions(authAppCodeValidator);
        verifyNoInteractions(codeStorageService);
    }

    private static Stream<Boolean> registration() {
        return Stream.of(true, false);
    }

    @ParameterizedTest
    @MethodSource("registration")
    void shouldReturn400AndBlockCodeWhenUserEnteredInvalidAuthAppCodeTooManyTimes(
            boolean registration) throws Json.JsonException {
        when(mfaCodeValidatorFactory.getMfaCodeValidator(any(), anyBoolean(), any()))
                .thenReturn(Optional.of(authAppCodeValidator));
        when(authAppCodeValidator.validateCode(CODE))
                .thenReturn(Optional.of(ErrorResponse.ERROR_1042));
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, VERIFY_EMAIL))
                .thenReturn(Optional.of(CODE));
        var result = makeCallWithCode(registration);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1042));
        assertThat(session.getVerifiedMfaMethodType(), equalTo(null));
        verify(codeStorageService)
                .saveBlockedForEmail(TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX, 900L);
        verify(authenticationService, never())
                .setMFAMethodVerifiedTrue(TEST_EMAIL_ADDRESS, MFAMethodType.AUTH_APP);
        verify(codeStorageService).deleteIncorrectMfaCodeAttemptsCount(TEST_EMAIL_ADDRESS);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_MAX_RETRIES_REACHED,
                        context.getAwsRequestId(),
                        session.getSessionId(),
                        CLIENT_ID,
                        SUBJECT_ID,
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE,
                        pair("mfa-type", MFAMethodType.AUTH_APP.getValue()));
    }

    @ParameterizedTest
    @MethodSource("registration")
    void shouldReturn400WhenUserEnteredInvalidAuthAppCode(boolean registration)
            throws Json.JsonException {
        when(mfaCodeValidatorFactory.getMfaCodeValidator(any(), anyBoolean(), any()))
                .thenReturn(Optional.of(authAppCodeValidator));
        when(authAppCodeValidator.validateCode(CODE))
                .thenReturn(Optional.of(ErrorResponse.ERROR_1043));
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, VERIFY_EMAIL))
                .thenReturn(Optional.of(CODE));
        var result = makeCallWithCode(registration);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1043));
        assertThat(session.getVerifiedMfaMethodType(), equalTo(null));
        verify(codeStorageService, never())
                .saveBlockedForEmail(TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX, 900L);
        verify(authenticationService, never())
                .setMFAMethodVerifiedTrue(TEST_EMAIL_ADDRESS, MFAMethodType.AUTH_APP);
        verify(codeStorageService, never()).deleteIncorrectMfaCodeAttemptsCount(TEST_EMAIL_ADDRESS);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.INVALID_CODE_SENT,
                        context.getAwsRequestId(),
                        session.getSessionId(),
                        CLIENT_ID,
                        SUBJECT_ID,
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE,
                        pair("mfa-type", MFAMethodType.AUTH_APP.getValue()));
    }

    private APIGatewayProxyResponseEvent makeCallWithCode(boolean registration)
            throws Json.JsonException {
        var event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(
                Map.of(
                        "Session-Id",
                        session.getSessionId(),
                        "Client-Session-Id",
                        CLIENT_SESSION_ID));
        var mfaCodeRequest = new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, CODE, registration);
        event.setBody(objectMapper.writeValueAsString(mfaCodeRequest));
        when(sessionService.getSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(session));
        when(clientSessionService.getClientSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(clientSession));
        when(clientSessionService.getClientSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(clientSession));
        return handler.handleRequest(event, context);
    }

    private AuthenticationRequest withAuthenticationRequest() {
        return new AuthenticationRequest.Builder(
                        new ResponseType(ResponseType.Value.CODE),
                        new Scope(OIDCScopeValue.OPENID),
                        new ClientID(CLIENT_ID),
                        URI.create("https://redirectUri"))
                .state(new State())
                .nonce(new Nonce())
                .build();
    }
}
