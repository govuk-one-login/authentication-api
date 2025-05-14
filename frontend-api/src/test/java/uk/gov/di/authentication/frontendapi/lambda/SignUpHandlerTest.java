package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
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
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.User;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.validation.PasswordValidator;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_CREATE_ACCOUNT_EMAIL_ALREADY_EXISTS;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.PASSWORD;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.VALID_HEADERS_WITHOUT_AUDIT_ENCODED;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
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
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private static final ClientID CLIENT_ID = new ClientID();
    private static final String CLIENT_NAME = "client-name";
    private static final String EMAIL = CommonTestVariables.EMAIL;

    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final byte[] SALT = SaltHelper.generateNewSalt();
    private static final URI REDIRECT_URI = URI.create("test-uri");
    private static final Subject INTERNAL_SUBJECT_ID = new Subject();
    private final String expectedCommonSubject =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    INTERNAL_SUBJECT_ID.getValue(), "test.account.gov.uk", SALT);
    private final AuthSessionItem authSessionItem =
            new AuthSessionItem()
                    .withSessionId(SESSION_ID)
                    .withAccountState(AuthSessionItem.AccountState.UNKNOWN)
                    .withClientId(CLIENT_ID.getValue());

    private SignUpHandler handler;

    private final Session session = new Session();
    private final ClientSession clientSession =
            new ClientSession(
                    generateAuthRequest().toParameters(), null, (VectorOfTrust) null, CLIENT_NAME);

    private static final AuditContext AUDIT_CONTEXT =
            new AuditContext(
                    CLIENT_ID.getValue(),
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    AuditService.UNKNOWN,
                    EMAIL,
                    IP_ADDRESS,
                    AuditService.UNKNOWN,
                    DI_PERSISTENT_SESSION_ID,
                    Optional.of(ENCODED_DEVICE_DETAILS));

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(SignUpHandler.class);

    @AfterEach
    void tearDown() {
        assertThat(logging.events(), not(hasItem(withMessageContaining(SESSION_ID))));
    }

    @BeforeEach
    void setUp() {
        when(configurationService.getTermsAndConditionsVersion()).thenReturn("1.0");
        when(configurationService.getInternalSectorUri()).thenReturn(INTERNAL_SECTOR_URI);
        when(user.getUserProfile()).thenReturn(userProfile);
        when(clientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(generateClientRegistry()));
        when(clientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(clientSession));
        when(authenticationService.getOrGenerateSalt(any(UserProfile.class))).thenReturn(SALT);
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
                        passwordValidator,
                        authSessionService);
    }

    @Test
    void shouldReturn200IfSignUpIsSuccessful() {
        when(authenticationService.userExists(EMAIL)).thenReturn(false);
        when(authenticationService.signUp(
                        eq(EMAIL), eq(PASSWORD), any(Subject.class), any(TermsAndConditions.class)))
                .thenReturn(user);
        when(userProfile.getSubjectID()).thenReturn(INTERNAL_SUBJECT_ID.getValue());
        usingValidSession();
        usingValidClientSession();
        withValidAuthSession();
        var body = format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(authenticationService)
                .signUp(eq(EMAIL), eq(PASSWORD), any(Subject.class), any(TermsAndConditions.class));

        assertThat(result, hasStatus(200));
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
                        FrontendAuditableEvent.AUTH_CREATE_ACCOUNT,
                        AUDIT_CONTEXT.withSubjectId(expectedCommonSubject),
                        pair("internalSubjectId", INTERNAL_SUBJECT_ID.getValue()),
                        pair("rpPairwiseId", expectedRpPairwiseId));

        verify(authSessionService)
                .updateSession(
                        argThat(
                                s ->
                                        s.getIsNewAccount() == AuthSessionItem.AccountState.NEW
                                                && Objects.equals(
                                                        s.getInternalCommonSubjectId(),
                                                        expectedCommonSubject)));
    }

    @Test
    void shouldUpdateAuthSession() {
        when(authenticationService.userExists(EMAIL)).thenReturn(false);
        when(authenticationService.signUp(
                        eq(EMAIL), eq(PASSWORD), any(Subject.class), any(TermsAndConditions.class)))
                .thenReturn(user);
        when(userProfile.getSubjectID()).thenReturn(INTERNAL_SUBJECT_ID.getValue());
        usingValidSession();
        usingValidClientSession();
        withValidAuthSession();
        var body = format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(authenticationService)
                .signUp(eq(EMAIL), eq(PASSWORD), any(Subject.class), any(TermsAndConditions.class));

        assertThat(result, hasStatus(200));
        verify(authSessionService)
                .updateSession(
                        argThat(s -> s.getIsNewAccount() == AuthSessionItem.AccountState.NEW));
    }

    @Test
    void checkCreateAccountAuditEventStillEmittedWhenTICFHeaderNotProvided() {
        when(authenticationService.userExists(EMAIL)).thenReturn(false);
        when(authenticationService.signUp(
                        eq(EMAIL), eq(PASSWORD), any(Subject.class), any(TermsAndConditions.class)))
                .thenReturn(user);
        when(userProfile.getSubjectID()).thenReturn(INTERNAL_SUBJECT_ID.getValue());
        usingValidSession();
        usingValidClientSession();
        withValidAuthSession();
        var body = format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS_WITHOUT_AUDIT_ENCODED, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        var expectedRpPairwiseId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        INTERNAL_SUBJECT_ID.getValue(), "test.com", SALT);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_CREATE_ACCOUNT,
                        AUDIT_CONTEXT
                                .withSubjectId(expectedCommonSubject)
                                .withTxmaAuditEncoded(Optional.empty()),
                        pair("internalSubjectId", INTERNAL_SUBJECT_ID.getValue()),
                        pair("rpPairwiseId", expectedRpPairwiseId));
    }

    @Test
    void shouldReturn400IfSessionIdMissing() {
        var body =
                format(
                        "{ \"password\": \"%s\", \"email\": \"%s\" }",
                        PASSWORD, EMAIL.toUpperCase());
        var event = apiRequestEventWithHeadersAndBody(Map.of(), body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1000));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400IfAnyRequestParametersAreMissing() {
        usingValidSession();
        withValidAuthSession();
        var body = format("{ \"email\": \"%s\" }", EMAIL.toUpperCase());
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400IfPasswordInvalid() {
        usingValidSession();
        withValidAuthSession();
        var body =
                format("{ \"password\": \"%s\", \"email\": \"%s\" }", "pwd", EMAIL.toUpperCase());
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1006));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400IfUserAlreadyExists() {
        when(authenticationService.userExists(EMAIL)).thenReturn(true);

        usingValidSession();
        usingValidClientSession();
        withValidAuthSession();

        var body =
                format(
                        "{ \"password\": \"%s\", \"email\": \"%s\" }",
                        PASSWORD, EMAIL.toUpperCase());
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1009));

        verify(auditService)
                .submitAuditEvent(AUTH_CREATE_ACCOUNT_EMAIL_ALREADY_EXISTS, AUDIT_CONTEXT);
    }

    @Test
    void checkCreateAccountEmailAlreadyExistsAuditEventStillEmittedWhenTICFHeaderNotProvided() {
        when(authenticationService.userExists(EMAIL)).thenReturn(true);
        usingValidSession();
        withValidAuthSession();
        var body =
                format(
                        "{ \"password\": \"%s\", \"email\": \"%s\" }",
                        PASSWORD, EMAIL.toUpperCase());
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS_WITHOUT_AUDIT_ENCODED, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));

        verify(auditService)
                .submitAuditEvent(
                        AUTH_CREATE_ACCOUNT_EMAIL_ALREADY_EXISTS,
                        AUDIT_CONTEXT.withTxmaAuditEncoded(Optional.empty()));
    }

    @Test
    void shouldReturn400IfNoAuthSessionPresent() {
        withNoAuthSession();
        usingValidSession();
        usingValidClientSession();

        var body =
                format(
                        "{ \"password\": \"%s\", \"email\": \"%s\" }",
                        PASSWORD, EMAIL.toUpperCase());
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1000));
        verifyNoInteractions(auditService);
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
        return new AuthenticationRequest.Builder(responseType, scope, CLIENT_ID, REDIRECT_URI)
                .state(state)
                .nonce(nonce)
                .build();
    }

    private void usingValidClientSession() {
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(clientSession));
    }

    private ClientRegistry generateClientRegistry() {
        return new ClientRegistry()
                .withClientID(CLIENT_ID.getValue())
                .withClientName("test-client")
                .withSectorIdentifierUri("https://test.com")
                .withSubjectType("pairwise");
    }

    private void withValidAuthSession() {
        when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(authSessionItem));
    }

    private void withNoAuthSession() {
        when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.empty());
    }
}
