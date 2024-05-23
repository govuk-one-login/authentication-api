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
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.SignUpResponse;
import uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.User;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.validation.PasswordValidator;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.PASSWORD;
import static uk.gov.di.authentication.frontendapi.lambda.StartHandlerTest.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.lambda.BaseFrontendHandler.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class SignUpHandlerTest {

    private final Context context = mock(Context.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final User user = mock(User.class);
    private final UserProfile userProfile = mock(UserProfile.class);
    private final AuditService auditService = mock(AuditService.class);
    private final CommonPasswordsService commonPasswordsService =
            mock(CommonPasswordsService.class);
    private final PasswordValidator passwordValidator = mock(PasswordValidator.class);
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    public static final ClientRegistry CLIENT =
            new ClientRegistry()
                    .withClientID(IdGenerator.generate())
                    .withSectorIdentifierUri("https://test.com");
    private static final String CLIENT_NAME = "client-name";
    private static final String EMAIL = CommonTestVariables.EMAIL;

    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final byte[] SALT = SaltHelper.generateNewSalt();
    private static final URI REDIRECT_URI = URI.create("test-uri");
    private static final Subject INTERNAL_SUBJECT_ID = new Subject();
    private final String expectedCommonSubject =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    INTERNAL_SUBJECT_ID.getValue(), "test.account.gov.uk", SALT);
    private static final Json objectMapper = SerializationService.getInstance();
    public static final String ENCODED_DEVICE_DETAILS =
            "YTtKVSlub1YlOSBTeEI4J3pVLVd7Jjl8VkBfREs2N3clZmN+fnU7fXNbcTJjKyEzN2IuUXIgMGttV058fGhUZ0xhenZUdldEblB8SH18XypwXUhWPXhYXTNQeURW%";

    private SignUpHandler handler;

    private final Session session = new Session(IdGenerator.generate());
    private final ClientSession clientSession =
            new ClientSession(
                    generateAuthRequest().toParameters(), null, (VectorOfTrust) null, CLIENT_NAME);

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(SignUpHandler.class);

    @AfterEach
    void tearDown() {
        assertThat(logging.events(), not(hasItem(withMessageContaining(session.getSessionId()))));
    }

    @BeforeEach
    void setUp() {
        when(configurationService.getTermsAndConditionsVersion()).thenReturn("1.0");
        when(configurationService.getInternalSectorUri()).thenReturn(INTERNAL_SECTOR_URI);
        when(user.getUserProfile()).thenReturn(userProfile);
        when(authenticationService.getOrGenerateSalt(any(UserProfile.class))).thenReturn(SALT);
        when(authenticationService.userExists(EMAIL)).thenReturn(false);
        when(clientService.getClient(CLIENT.getClientID())).thenReturn(Optional.of(CLIENT));
        when(clientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(clientSession));
        when(authenticationService.signUp(
                        eq(EMAIL), eq(PASSWORD), any(Subject.class), any(TermsAndConditions.class)))
                .thenReturn(user);
        when(userProfile.getSubjectID()).thenReturn(INTERNAL_SUBJECT_ID.getValue());
        doReturn(Optional.of(ErrorResponse.ERROR_1006)).when(passwordValidator).validate("pwd");

        handler =
                new SignUpHandler(
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        auditService,
                        commonPasswordsService,
                        passwordValidator);
    }

    @Test
    void shouldReturn200IfSignUpIsSuccessful() {
        Map<String, String> headers = getHeadersWithoutTxmaAuditEncoded();
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS);

        usingValidSession();
        usingValidClientSession();
        APIGatewayProxyRequestEvent event =
                requestEvent(
                        headers,
                        format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(authenticationService)
                .signUp(eq(EMAIL), eq(PASSWORD), any(Subject.class), any(TermsAndConditions.class));
        verify(sessionService).save(argThat((session) -> session.getEmailAddress().equals(EMAIL)));

        assertThat(result, hasStatus(200));
        var signUpResponse =
                objectMapper.readValueUnchecked(result.getBody(), SignUpResponse.class);
        assertThat(signUpResponse.isConsentRequired(), equalTo(false));
        verify(authenticationService)
                .signUp(
                        eq(EMAIL),
                        eq("computer-1"),
                        any(Subject.class),
                        any(TermsAndConditions.class));
        var expectedRpPairwiseId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        INTERNAL_SUBJECT_ID.getValue(), "test.com", SALT);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CREATE_ACCOUNT,
                        CLIENT.getClientID(),
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        expectedCommonSubject,
                        EMAIL,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        "some-persistent-id-value",
                        new AuditService.RestrictedSection(Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("internalSubjectId", INTERNAL_SUBJECT_ID.getValue()),
                        pair("rpPairwiseId", expectedRpPairwiseId));

        verify(sessionService)
                .save(argThat(session -> session.isNewAccount() == Session.AccountState.NEW));
        verify(sessionService, atLeastOnce())
                .save(
                        argThat(
                                t ->
                                        t.getInternalCommonSubjectIdentifier()
                                                .equals(expectedCommonSubject)));
    }

    @Test
    void checkCreateAccountAuditEventStillEmittedWhenTICFHeaderNotProvided() {
        usingValidSession();
        usingValidClientSession();

        APIGatewayProxyRequestEvent event =
                requestEvent(
                        getHeadersWithoutTxmaAuditEncoded(),
                        format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        var expectedRpPairwiseId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        INTERNAL_SUBJECT_ID.getValue(), "test.com", SALT);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CREATE_ACCOUNT,
                        CLIENT.getClientID(),
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        expectedCommonSubject,
                        EMAIL,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        "some-persistent-id-value",
                        AuditService.RestrictedSection.empty,
                        pair("internalSubjectId", INTERNAL_SUBJECT_ID.getValue()),
                        pair("rpPairwiseId", expectedRpPairwiseId));
    }

    @Test
    void shouldReturn400IfSessionIdMissing() {
        APIGatewayProxyRequestEvent event =
                requestEvent(
                        Collections.emptyMap(),
                        format(
                                "{ \"password\": \"%s\", \"email\": \"%s\" }",
                                PASSWORD, EMAIL.toUpperCase()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1000));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400IfAnyRequestParametersAreMissing() {
        usingValidSession();

        APIGatewayProxyRequestEvent event =
                requestEvent(
                        getHeadersWithoutTxmaAuditEncoded(),
                        format("{ \"email\": \"%s\" }", EMAIL.toUpperCase()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400IfPasswordInvalid() {
        usingValidSession();
        String format =
                format("{ \"password\": \"%s\", \"email\": \"%s\" }", "pwd", EMAIL.toUpperCase());

        APIGatewayProxyRequestEvent event =
                requestEvent(getHeadersWithoutTxmaAuditEncoded(), format);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1006));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400IfUserAlreadyExists() {
        when(authenticationService.userExists(eq("joe.bloggs@test.com"))).thenReturn(true);

        usingValidSession();
        var headers = getHeadersWithoutTxmaAuditEncoded();
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS);

        APIGatewayProxyRequestEvent event =
                requestEvent(
                        headers,
                        format(
                                "{ \"password\": \"%s\", \"email\": \"%s\" }",
                                PASSWORD, EMAIL.toUpperCase()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1009));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CREATE_ACCOUNT_EMAIL_ALREADY_EXISTS,
                        CLIENT.getClientID(),
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        AuditService.UNKNOWN,
                        "joe.bloggs@test.com",
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        "some-persistent-id-value",
                        new AuditService.RestrictedSection(Optional.of(ENCODED_DEVICE_DETAILS)));
    }

    @Test
    void checkCreateAccountEmailAlreadyExistsAuditEventStillEmittedWhenTICFHeaderNotProvided() {
        when(authenticationService.userExists(eq("joe.bloggs@test.com"))).thenReturn(true);
        usingValidSession();
        APIGatewayProxyRequestEvent event =
                requestEvent(
                        getHeadersWithoutTxmaAuditEncoded(),
                        format(
                                "{ \"password\": \"%s\", \"email\": \"%s\" }",
                                PASSWORD, EMAIL.toUpperCase()));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CREATE_ACCOUNT_EMAIL_ALREADY_EXISTS,
                        CLIENT.getClientID(),
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        AuditService.UNKNOWN,
                        "joe.bloggs@test.com",
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        "some-persistent-id-value",
                        AuditService.RestrictedSection.empty);
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
    }

    public static AuthenticationRequest generateAuthRequest() {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        State state = new State();
        Scope scope = new Scope();
        Nonce nonce = new Nonce();
        scope.add(OIDCScopeValue.OPENID);
        scope.add("phone");
        scope.add("email");
        return new AuthenticationRequest.Builder(
                        responseType, scope, new ClientID(CLIENT.getClientID()), REDIRECT_URI)
                .state(state)
                .nonce(nonce)
                .build();
    }

    private void usingValidClientSession() {
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(clientSession));
    }

    private Map<String, String> getHeadersWithoutTxmaAuditEncoded() {
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, "some-persistent-id-value");
        headers.put("Session-Id", session.getSessionId());
        headers.put(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID);
        return headers;
    }

    private APIGatewayProxyRequestEvent requestEvent(Map<String, String> headers, String body) {
        return new APIGatewayProxyRequestEvent()
                .withRequestContext(contextWithSourceIp("123.123.123.123"))
                .withHeaders(headers)
                .withBody(body);
    }
}
