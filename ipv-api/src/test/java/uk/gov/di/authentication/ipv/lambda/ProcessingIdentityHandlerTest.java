package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.ipv.entity.ProcessingIdentityResponse;
import uk.gov.di.authentication.ipv.entity.ProcessingIdentityStatus;
import uk.gov.di.orchestration.shared.entity.AccountInterventionStatus;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.ErrorResponse;
import uk.gov.di.orchestration.shared.entity.IdentityCredentials;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.entity.UserProfile;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.AccountInterventionService;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.ClientSessionService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;
import uk.gov.di.orchestration.shared.services.DynamoService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.SessionService;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.orchestration.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.orchestration.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class ProcessingIdentityHandlerTest {

    public static final String CLIENT_SESSION_ID = "known-client-session-id";
    public static final String SESSION_ID = "some-session-id";
    private static final String EMAIL_ADDRESS = "test@test.com";
    private static final String CLIENT_ID = "test-client-id";
    private static final String CLIENT_NAME = "test-client-name";
    private static final String PHONE_NUMBER = "01234567890";
    private static final Subject PAIRWISE_SUBJECT = new Subject();
    private static final Date CREATED_DATE_TIME = NowHelper.nowMinus(30, ChronoUnit.SECONDS);
    private static final Date UPDATED_DATE_TIME = NowHelper.now();
    private static final String PUBLIC_SUBJECT_ID = new Subject("public-subject-id-2").getValue();
    private static final String SUBJECT_ID = new Subject("subject-id-3").getValue();
    private static final ByteBuffer SALT =
            ByteBuffer.wrap("a-test-salt".getBytes(StandardCharsets.UTF_8));
    private static final URI REDIRECT_URI = URI.create("http://localhost/oidc/redirect");
    private static final String ENVIRONMENT = "test-environment";

    private final Context context = mock(Context.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final DynamoIdentityService dynamoIdentityService = mock(DynamoIdentityService.class);
    private final AccountInterventionService accountInterventionService =
            mock(AccountInterventionService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final Session session = new Session(SESSION_ID);
    private final APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
    protected final Json objectMapper = SerializationService.getInstance();
    private ProcessingIdentityHandler handler;

    private static Stream<Arguments> aisResults() {
        return Stream.of(
                Arguments.of(new AccountInterventionStatus(false, false, false, false), ""),
                Arguments.of(
                        new AccountInterventionStatus(true, false, false, false),
                        "Account is blocked"),
                Arguments.of(
                        new AccountInterventionStatus(false, true, false, false),
                        "Account is suspended, requires a password reset, or requires identity to be reproved"),
                Arguments.of(
                        new AccountInterventionStatus(false, true, true, false),
                        "Account is suspended, requires a password reset, or requires identity to be reproved"),
                Arguments.of(
                        new AccountInterventionStatus(false, true, false, true),
                        "Account is suspended, requires a password reset, or requires identity to be reproved"),
                Arguments.of(
                        new AccountInterventionStatus(false, true, true, true),
                        "Account is suspended, requires a password reset, or requires identity to be reproved"),
                Arguments.of(
                        new AccountInterventionStatus(false, false, true, false),
                        "Account is suspended, requires a password reset, or requires identity to be reproved"),
                Arguments.of(
                        new AccountInterventionStatus(false, false, false, true),
                        "Account is suspended, requires a password reset, or requires identity to be reproved"));
    }

    @BeforeEach
    void setup() {
        var userProfile = generateUserProfile();
        when(dynamoClientService.getClient(CLIENT_ID))
                .thenReturn(Optional.of(generateClientRegistry()));
        when(dynamoService.getUserProfileFromEmail(EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(SALT.array());
        when(configurationService.getEnvironment()).thenReturn(ENVIRONMENT);
        Map<String, String> headers = new HashMap<>();
        headers.put(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID);
        headers.put(SESSION_ID_HEADER, SESSION_ID);
        event.setHeaders(headers);
        event.setBody(format("{ \"email\": \"%s\"}", EMAIL_ADDRESS));
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        handler =
                new ProcessingIdentityHandler(
                        dynamoIdentityService,
                        accountInterventionService,
                        sessionService,
                        clientSessionService,
                        dynamoClientService,
                        dynamoService,
                        configurationService,
                        auditService,
                        cloudwatchMetricsService);
    }

    @Test
    void shouldReturnErrorIfSessionIsNotFound() throws Json.JsonException {
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1000)));
        verifyNoInteractions(cloudwatchMetricsService);
    }

    @Test
    void shouldReturnCOMPLETEDStatusWhenIdentityCredentialIsPresent() throws Json.JsonException {
        usingValidSession();
        var identityCredentials =
                new IdentityCredentials()
                        .withSubjectID(PAIRWISE_SUBJECT.getValue())
                        .withAdditionalClaims(Collections.emptyMap())
                        .withCoreIdentityJWT("a-core-identity");
        when(dynamoIdentityService.getIdentityCredentials(anyString()))
                .thenReturn(Optional.of(identityCredentials));
        when(clientSessionService.getClientSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(getClientSession()));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertThat(
                result,
                hasBody(
                        objectMapper.writeValueAsString(
                                new ProcessingIdentityResponse(
                                        ProcessingIdentityStatus.COMPLETED))));
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "ProcessingIdentity",
                        Map.of(
                                "Environment",
                                ENVIRONMENT,
                                "Status",
                                ProcessingIdentityStatus.COMPLETED.toString()));
    }

    @Test
    void
            shouldMakeAndAuditAISCallIfAccountInterventionServiceAuditIsEnabledAndProcessingStatusIsCOMPLETED()
                    throws Json.JsonException {
        usingValidSession();
        var identityCredentials =
                new IdentityCredentials()
                        .withSubjectID(PAIRWISE_SUBJECT.getValue())
                        .withAdditionalClaims(Collections.emptyMap())
                        .withCoreIdentityJWT("a-core-identity");
        when(dynamoIdentityService.getIdentityCredentials(anyString()))
                .thenReturn(Optional.of(identityCredentials));
        when(clientSessionService.getClientSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(getClientSession()));
        when(configurationService.isAccountInterventionServiceActionEnabled()).thenReturn(true);
        when(accountInterventionService.getAccountStatus(anyString()))
                .thenReturn(new AccountInterventionStatus(false, false, false, false));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertThat(
                result,
                hasBody(
                        objectMapper.writeValueAsString(
                                new ProcessingIdentityResponse(
                                        ProcessingIdentityStatus.COMPLETED))));
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "ProcessingIdentity",
                        Map.of(
                                "Environment",
                                ENVIRONMENT,
                                "Status",
                                ProcessingIdentityStatus.COMPLETED.toString()));
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "AISResult",
                        Map.of(
                                "blocked", "false",
                                "suspended", "false",
                                "resetPassword", "false",
                                "reproveIdentity", "false"));
    }

    @ParameterizedTest
    @MethodSource("aisResults")
    void shouldInterveneIfAccountInterventionServiceAuditIsEnabledAndProcessingStatusIsCOMPLETED(
            AccountInterventionStatus aisResult, String expectedLogMessage)
            throws Json.JsonException {
        usingValidSession();
        var outputStreamCaptor = new ByteArrayOutputStream();
        System.setOut(new PrintStream(outputStreamCaptor));
        var identityCredentials =
                new IdentityCredentials()
                        .withSubjectID(PAIRWISE_SUBJECT.getValue())
                        .withAdditionalClaims(Collections.emptyMap())
                        .withCoreIdentityJWT("a-core-identity");
        when(dynamoIdentityService.getIdentityCredentials(anyString()))
                .thenReturn(Optional.of(identityCredentials));
        when(clientSessionService.getClientSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(getClientSession()));
        when(configurationService.isAccountInterventionServiceActionEnabled()).thenReturn(true);
        when(configurationService.isAccountInterventionServiceCallEnabled()).thenReturn(true);
        when(accountInterventionService.getAccountStatus(anyString())).thenReturn(aisResult);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertThat(
                result,
                hasBody(
                        objectMapper.writeValueAsString(
                                new ProcessingIdentityResponse(
                                        ProcessingIdentityStatus.COMPLETED))));
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "ProcessingIdentity",
                        Map.of(
                                "Environment",
                                ENVIRONMENT,
                                "Status",
                                ProcessingIdentityStatus.COMPLETED.toString()));
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "AISResult",
                        Map.of(
                                "blocked", String.valueOf(aisResult.blocked()),
                                "suspended", String.valueOf(aisResult.suspended()),
                                "resetPassword", String.valueOf(aisResult.resetPassword()),
                                "reproveIdentity", String.valueOf(aisResult.reproveIdentity())));

        assertThat(outputStreamCaptor.toString(), containsString(expectedLogMessage));

        System.setOut(System.out);
    }

    @Test
    void shouldReturnPROCESSINGStatusWhenEntryIsInDynamoButNoIdentityCredentialIsPresent()
            throws Json.JsonException {
        usingValidSession();
        var identityCredentials =
                new IdentityCredentials()
                        .withSubjectID(PAIRWISE_SUBJECT.getValue())
                        .withAdditionalClaims(Collections.emptyMap());
        when(dynamoIdentityService.getIdentityCredentials(anyString()))
                .thenReturn(Optional.of(identityCredentials));
        when(clientSessionService.getClientSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(getClientSession()));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertThat(
                result,
                hasBody(
                        objectMapper.writeValueAsString(
                                new ProcessingIdentityResponse(
                                        ProcessingIdentityStatus.PROCESSING))));
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "ProcessingIdentity",
                        Map.of(
                                "Environment",
                                ENVIRONMENT,
                                "Status",
                                ProcessingIdentityStatus.PROCESSING.toString()));
    }

    @Test
    void shouldReturnERRORStatusWhenNoEntryIsFoundInDynamoAfterSecondAttempt()
            throws Json.JsonException {
        session.incrementProcessingIdentityAttempts();
        usingValidSession();
        when(dynamoIdentityService.getIdentityCredentials(PAIRWISE_SUBJECT.getValue()))
                .thenReturn(Optional.empty());
        when(clientSessionService.getClientSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(getClientSession()));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertThat(
                result,
                hasBody(
                        objectMapper.writeValueAsString(
                                new ProcessingIdentityResponse(ProcessingIdentityStatus.ERROR))));
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "ProcessingIdentity",
                        Map.of(
                                "Environment",
                                ENVIRONMENT,
                                "Status",
                                ProcessingIdentityStatus.ERROR.toString()));
    }

    @Test
    void shouldReturnNO_ENTRYStatusWhenNoEntryIsFoundInDynamoOnFirstAttempt()
            throws Json.JsonException {
        usingValidSession();
        when(dynamoIdentityService.getIdentityCredentials(PAIRWISE_SUBJECT.getValue()))
                .thenReturn(Optional.empty());
        when(clientSessionService.getClientSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(getClientSession()));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertThat(
                result,
                hasBody(
                        objectMapper.writeValueAsString(
                                new ProcessingIdentityResponse(
                                        ProcessingIdentityStatus.NO_ENTRY))));
        assertThat(session.getProcessingIdentityAttempts(), equalTo(0));
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "ProcessingIdentity",
                        Map.of(
                                "Environment",
                                ENVIRONMENT,
                                "Status",
                                ProcessingIdentityStatus.NO_ENTRY.toString()));
    }

    private ClientSession getClientSession() {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                responseType,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create("http://localhost/redirect"))
                        .build();

        return new ClientSession(
                authRequest.toParameters(), null, mock(VectorOfTrust.class), CLIENT_NAME);
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
    }

    private ClientRegistry generateClientRegistry() {
        return new ClientRegistry()
                .withRedirectUrls(singletonList(REDIRECT_URI.toString()))
                .withClientID(CLIENT_ID)
                .withContacts(singletonList("joe.bloggs@digital.cabinet-office.gov.uk"))
                .withPublicKey(null)
                .withSectorIdentifierUri("http://sector-identifier")
                .withScopes(singletonList("openid"))
                .withCookieConsentShared(true)
                .withSubjectType("pairwise");
    }

    private UserProfile generateUserProfile() {
        return new UserProfile()
                .withEmail(EMAIL_ADDRESS)
                .withEmailVerified(true)
                .withPhoneNumber(PHONE_NUMBER)
                .withPhoneNumberVerified(true)
                .withPublicSubjectID(PUBLIC_SUBJECT_ID)
                .withSubjectID(SUBJECT_ID)
                .withSalt(SALT)
                .withCreated(CREATED_DATE_TIME.toString())
                .withUpdated(UPDATED_DATE_TIME.toString());
    }
}
