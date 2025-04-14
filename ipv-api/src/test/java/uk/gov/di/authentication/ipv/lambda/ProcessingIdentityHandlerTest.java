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
import software.amazon.awssdk.core.SdkBytes;
import uk.gov.di.authentication.ipv.entity.ProcessingIdentityInterventionResponse;
import uk.gov.di.authentication.ipv.entity.ProcessingIdentityResponse;
import uk.gov.di.authentication.ipv.entity.ProcessingIdentityStatus;
import uk.gov.di.orchestration.shared.entity.AccountIntervention;
import uk.gov.di.orchestration.shared.entity.AccountInterventionState;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.DestroySessionsRequest;
import uk.gov.di.orchestration.shared.entity.ErrorResponse;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchIdentityCredentials;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.entity.UserProfile;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.AccountInterventionService;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;
import uk.gov.di.orchestration.shared.services.DynamoService;
import uk.gov.di.orchestration.shared.services.LogoutService;
import uk.gov.di.orchestration.shared.services.OrchClientSessionService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.SessionService;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.orchestration.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
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
    private static final Date CREATED_DATE_TIME = NowHelper.nowMinus(30, ChronoUnit.SECONDS);
    private static final Date UPDATED_DATE_TIME = NowHelper.now();
    private static final String PUBLIC_SUBJECT_ID = new Subject("public-subject-id-2").getValue();
    private static final String SUBJECT_ID = new Subject("subject-id-3").getValue();
    private static final ByteBuffer SALT =
            ByteBuffer.wrap("a-test-salt".getBytes(StandardCharsets.UTF_8));
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final String PAIRWISE_SUBJECT =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    SUBJECT_ID,
                    URI.create(INTERNAL_SECTOR_URI),
                    SdkBytes.fromByteBuffer(SALT).asByteArray());

    private static final URI REDIRECT_URI = URI.create("http://localhost/oidc/redirect");
    private static final String ENVIRONMENT = "test-environment";

    private final Context context = mock(Context.class);
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
    private final LogoutService logoutService = mock(LogoutService.class);
    private final OrchSessionService orchSessionService = mock(OrchSessionService.class);
    private final OrchClientSessionService orchClientSessionService =
            mock(OrchClientSessionService.class);
    private final Session session = new Session();
    private final OrchSessionItem orchSession = new OrchSessionItem(SESSION_ID);
    private final APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
    protected final Json objectMapper = SerializationService.getInstance();
    private ProcessingIdentityHandler handler;

    @BeforeEach
    void setup() {
        var userProfile = generateUserProfile();
        when(dynamoClientService.getClient(CLIENT_ID))
                .thenReturn(Optional.of(generateClientRegistry()));
        when(dynamoService.getUserProfileFromEmail(EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(SALT.array());
        when(configurationService.getEnvironment()).thenReturn(ENVIRONMENT);
        when(configurationService.getInternalSectorURI()).thenReturn(INTERNAL_SECTOR_URI);
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
                        dynamoClientService,
                        dynamoService,
                        configurationService,
                        auditService,
                        cloudwatchMetricsService,
                        logoutService,
                        orchSessionService,
                        orchClientSessionService);
    }

    @Test
    void shouldReturnErrorIfSessionIsNotFound() throws Json.JsonException {
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1000)));
        verifyNoInteractions(cloudwatchMetricsService);
    }

    @Test
    void shouldReturnErrorIfOrchSessionIsNotFound() throws Json.JsonException {
        when(sessionService.getSession(anyString())).thenReturn(Optional.of(session));
        when(orchSessionService.getSession(anyString())).thenReturn(Optional.empty());

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1000)));
        verifyNoInteractions(cloudwatchMetricsService);
    }

    @Test
    void shouldReturnCOMPLETEDStatusWhenIdentityCredentialIsPresent() throws Json.JsonException {
        usingValidSession();
        var identityCredentials =
                new OrchIdentityCredentials()
                        .withClientSessionId(CLIENT_SESSION_ID)
                        .withSubjectID(PAIRWISE_SUBJECT)
                        .withAdditionalClaims(Collections.emptyMap())
                        .withCoreIdentityJWT("a-core-identity");
        when(dynamoIdentityService.getIdentityCredentials(anyString()))
                .thenReturn(Optional.of(identityCredentials));
        when(orchClientSessionService.getClientSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(getOrchClientSession()));
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
        assertThat(orchSession.getProcessingIdentityAttempts(), equalTo(1));
    }

    @Test
    void shouldCallAISIfProcessingStatusIsCOMPLETED() throws Json.JsonException {
        usingValidSession();
        var identityCredentials =
                new OrchIdentityCredentials()
                        .withClientSessionId(CLIENT_SESSION_ID)
                        .withSubjectID(PAIRWISE_SUBJECT)
                        .withAdditionalClaims(Collections.emptyMap())
                        .withCoreIdentityJWT("a-core-identity");
        when(dynamoIdentityService.getIdentityCredentials(anyString()))
                .thenReturn(Optional.of(identityCredentials));
        when(orchClientSessionService.getClientSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(getOrchClientSession()));
        when(configurationService.isAccountInterventionServiceActionEnabled()).thenReturn(true);
        when(accountInterventionService.getAccountIntervention(anyString(), any()))
                .thenReturn(
                        new AccountIntervention(
                                new AccountInterventionState(false, false, false, false)));

        var result = handler.handleRequest(event, context);
        verify(accountInterventionService).getAccountIntervention(eq(PAIRWISE_SUBJECT), any());
        assertThat(result, hasStatus(200));
        assertThat(
                result,
                hasBody(
                        objectMapper.writeValueAsString(
                                new ProcessingIdentityResponse(
                                        ProcessingIdentityStatus.COMPLETED))));
    }

    @Test
    void shouldInterveneIfAccountInterventionServiceActionIsEnabledAndProcessingStatusIsCOMPLETED()
            throws Json.JsonException {
        usingValidSession();
        var identityCredentials =
                new OrchIdentityCredentials()
                        .withSubjectID(PAIRWISE_SUBJECT)
                        .withAdditionalClaims(Collections.emptyMap())
                        .withCoreIdentityJWT("a-core-identity");
        AccountIntervention intervention =
                new AccountIntervention(new AccountInterventionState(false, true, false, false));
        when(dynamoIdentityService.getIdentityCredentials(anyString()))
                .thenReturn(Optional.of(identityCredentials));
        when(orchClientSessionService.getClientSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(getOrchClientSession()));
        when(configurationService.isAccountInterventionServiceActionEnabled()).thenReturn(true);
        when(accountInterventionService.getAccountIntervention(anyString(), any()))
                .thenReturn(intervention);
        String redirectUrl = "https://example.com/intervention";
        when(logoutService.handleAccountInterventionLogout(any(), any(), any(), any(), any()))
                .thenReturn(
                        generateApiGatewayProxyResponse(
                                302, "", Map.of(ResponseHeaders.LOCATION, redirectUrl), null));

        var result = handler.handleRequest(event, context);

        verify(logoutService)
                .handleAccountInterventionLogout(
                        new DestroySessionsRequest(SESSION_ID, List.of(), null),
                        null,
                        event,
                        CLIENT_ID,
                        intervention);
        assertThat(result, hasStatus(200));
        assertThat(
                result,
                hasBody(
                        objectMapper.writeValueAsString(
                                new ProcessingIdentityInterventionResponse(
                                        ProcessingIdentityStatus.INTERVENTION, redirectUrl))));
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
    void shouldReturnPROCESSINGStatusWhenEntryIsInDynamoButNoIdentityCredentialIsPresent()
            throws Json.JsonException {
        usingValidSession();
        var identityCredentials =
                new OrchIdentityCredentials()
                        .withSubjectID(PAIRWISE_SUBJECT)
                        .withAdditionalClaims(Collections.emptyMap());
        when(dynamoIdentityService.getIdentityCredentials(anyString()))
                .thenReturn(Optional.of(identityCredentials));
        when(orchClientSessionService.getClientSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(getOrchClientSession()));
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
        orchSession.incrementProcessingIdentityAttempts();
        usingValidSession();
        when(dynamoIdentityService.getIdentityCredentials(CLIENT_SESSION_ID))
                .thenReturn(Optional.empty());
        when(orchClientSessionService.getClientSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(getOrchClientSession()));

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
        when(dynamoIdentityService.getIdentityCredentials(CLIENT_SESSION_ID))
                .thenReturn(Optional.empty());
        when(orchClientSessionService.getClientSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(getOrchClientSession()));
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertThat(
                result,
                hasBody(
                        objectMapper.writeValueAsString(
                                new ProcessingIdentityResponse(
                                        ProcessingIdentityStatus.NO_ENTRY))));
        assertThat(session.getProcessingIdentityAttempts(), equalTo(0));
        assertThat(orchSession.getProcessingIdentityAttempts(), equalTo(0));
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "ProcessingIdentity",
                        Map.of(
                                "Environment",
                                ENVIRONMENT,
                                "Status",
                                ProcessingIdentityStatus.NO_ENTRY.toString()));
    }

    private OrchClientSessionItem getOrchClientSession() {
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

        return new OrchClientSessionItem(
                CLIENT_SESSION_ID, authRequest.toParameters(), null, List.of(), CLIENT_NAME);
    }

    private void usingValidSession() {
        when(sessionService.getSession(anyString())).thenReturn(Optional.of(session));
        when(orchSessionService.getSession(anyString())).thenReturn(Optional.of(orchSession));
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
