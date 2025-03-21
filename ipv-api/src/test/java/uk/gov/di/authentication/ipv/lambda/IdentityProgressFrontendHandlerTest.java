package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.approvaltests.Approvals;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.entity.IdentityProgressResponse;
import uk.gov.di.authentication.ipv.entity.IdentityProgressStatus;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.entity.ErrorResponse;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchIdentityCredentials;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.AuthenticationUserInfoStorageService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;
import uk.gov.di.orchestration.shared.services.OrchClientSessionService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.SessionService;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
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

public class IdentityProgressFrontendHandlerTest {

    public static final String CLIENT_SESSION_ID = "known-client-session-id";
    public static final String SESSION_ID = "some-session-id";
    private static final String CLIENT_ID = "test-client-id";
    private static final String CLIENT_NAME = "test-client-name";
    private static final String ENVIRONMENT = "test-environment";
    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private static final State STATE = new State("test-state");
    private static final TxmaAuditUser USER =
            TxmaAuditUser.user()
                    .withGovukSigninJourneyId(CLIENT_SESSION_ID)
                    .withSessionId(SESSION_ID)
                    .withIpAddress("123.123.123.123")
                    .withPersistentSessionId("unknown");

    private static final String INTERNAL_COMMON_SUBJECT_ID = "internal-common-subject-id";
    private static final String RP_PAIRWISE_ID = "rp_pairwise_id";
    private static final UserInfo AUTH_USER_INFO =
            new UserInfo(
                    new JWTClaimsSet.Builder()
                            .subject(INTERNAL_COMMON_SUBJECT_ID)
                            .claim("rp_pairwise_id", RP_PAIRWISE_ID)
                            .build());

    private final Context context = mock(Context.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final DynamoIdentityService dynamoIdentityService = mock(DynamoIdentityService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final AuthenticationUserInfoStorageService userInfoStorageService =
            mock(AuthenticationUserInfoStorageService.class);
    private final OrchSessionService orchSessionService = mock(OrchSessionService.class);
    private final OrchClientSessionService orchClientSessionService =
            mock(OrchClientSessionService.class);
    private final Session session = new Session();
    private final OrchSessionItem orchSession =
            new OrchSessionItem(SESSION_ID).withInternalCommonSubjectId(INTERNAL_COMMON_SUBJECT_ID);
    private final APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
    protected final Json objectMapper = SerializationService.getInstance();
    private IdentityProgressFrontendHandler handler;

    @BeforeEach
    void setup() throws ParseException {
        when(configurationService.getEnvironment()).thenReturn(ENVIRONMENT);
        when(userInfoStorageService.getAuthenticationUserInfo(
                        INTERNAL_COMMON_SUBJECT_ID, CLIENT_SESSION_ID))
                .thenReturn(Optional.of(AUTH_USER_INFO));
        Map<String, String> headers = new HashMap<>();
        headers.put(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID);
        headers.put(SESSION_ID_HEADER, SESSION_ID);
        event.setHeaders(headers);
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        handler =
                new IdentityProgressFrontendHandler(
                        configurationService,
                        dynamoIdentityService,
                        auditService,
                        cloudwatchMetricsService,
                        sessionService,
                        userInfoStorageService,
                        orchSessionService,
                        orchClientSessionService);
    }

    @Test
    void shouldReturnErrorIfSessionIsNotFound() throws Json.JsonException {
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1000)));
        verifyNoInteractions(cloudwatchMetricsService, auditService);
    }

    @Test
    void shouldReturnErrorIfOrchSessionIsNotFound() throws Json.JsonException {
        when(sessionService.getSession(anyString())).thenReturn(Optional.of(session));
        when(orchSessionService.getSession(anyString())).thenReturn(Optional.empty());
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1000)));
        verifyNoInteractions(cloudwatchMetricsService, auditService);
    }

    @Test
    void shouldReturnErrorWhenInternalCommonSubjectIdIsNullOnOrchSession()
            throws Json.JsonException {
        when(sessionService.getSession(anyString())).thenReturn(Optional.of(session));
        when(orchSessionService.getSession(anyString()))
                .thenReturn(
                        Optional.of(
                                new OrchSessionItem(SESSION_ID).withInternalCommonSubjectId(null)));
        when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(getOrchClientSession()));
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1000)));
        verifyNoInteractions(cloudwatchMetricsService, auditService);
    }

    @Test
    void shouldReturnCOMPLETEDStatusWhenIdentityCredentialIsPresent() throws Json.JsonException {
        usingValidSession();
        var identityCredentials =
                new OrchIdentityCredentials()
                        .withSubjectID(INTERNAL_COMMON_SUBJECT_ID)
                        .withAdditionalClaims(Collections.emptyMap())
                        .withCoreIdentityJWT("a-core-identity");
        when(dynamoIdentityService.getIdentityCredentials(anyString()))
                .thenReturn(Optional.of(identityCredentials));
        when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(getOrchClientSession()));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertThat(
                result,
                hasBody(
                        objectMapper.writeValueAsString(
                                new IdentityProgressResponse(
                                        IdentityProgressStatus.COMPLETED,
                                        CLIENT_NAME,
                                        REDIRECT_URI,
                                        STATE))));
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "ProcessingIdentity",
                        Map.of(
                                "Environment",
                                ENVIRONMENT,
                                "Status",
                                IdentityProgressStatus.COMPLETED.toString()));

        verify(auditService)
                .submitAuditEvent(IPVAuditableEvent.PROCESSING_IDENTITY_REQUEST, CLIENT_ID, USER);
        assertThat(session.getProcessingIdentityAttempts(), equalTo(1));
        assertThat(orchSession.getProcessingIdentityAttempts(), equalTo(1));
    }

    @Test
    void shouldReturnPROCESSINGStatusWhenEntryIsInDynamoButNoIdentityCredentialIsPresent()
            throws Json.JsonException {
        usingValidSession();
        var identityCredentials =
                new OrchIdentityCredentials()
                        .withSubjectID(INTERNAL_COMMON_SUBJECT_ID)
                        .withAdditionalClaims(Collections.emptyMap());
        when(dynamoIdentityService.getIdentityCredentials(anyString()))
                .thenReturn(Optional.of(identityCredentials));
        when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(getOrchClientSession()));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertThat(
                result,
                hasBody(
                        objectMapper.writeValueAsString(
                                new IdentityProgressResponse(
                                        IdentityProgressStatus.PROCESSING,
                                        CLIENT_NAME,
                                        REDIRECT_URI,
                                        STATE))));
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "ProcessingIdentity",
                        Map.of(
                                "Environment",
                                ENVIRONMENT,
                                "Status",
                                IdentityProgressStatus.PROCESSING.toString()));

        verify(auditService)
                .submitAuditEvent(IPVAuditableEvent.PROCESSING_IDENTITY_REQUEST, CLIENT_ID, USER);
    }

    @Test
    void shouldReturnERRORStatusWhenNoEntryIsFoundInDynamoAfterSecondAttempt()
            throws Json.JsonException {
        session.incrementProcessingIdentityAttempts();
        usingValidSession();
        when(dynamoIdentityService.getIdentityCredentials(CLIENT_SESSION_ID))
                .thenReturn(Optional.empty());
        when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(getOrchClientSession()));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertThat(
                result,
                hasBody(
                        objectMapper.writeValueAsString(
                                new IdentityProgressResponse(
                                        IdentityProgressStatus.ERROR,
                                        CLIENT_NAME,
                                        REDIRECT_URI,
                                        STATE))));
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "ProcessingIdentity",
                        Map.of(
                                "Environment",
                                ENVIRONMENT,
                                "Status",
                                IdentityProgressStatus.ERROR.toString()));

        verify(auditService)
                .submitAuditEvent(IPVAuditableEvent.PROCESSING_IDENTITY_REQUEST, CLIENT_ID, USER);
    }

    @Test
    void shouldReturnNO_ENTRYStatusWhenNoEntryIsFoundInDynamoOnFirstAttempt()
            throws Json.JsonException {
        usingValidSession();
        when(dynamoIdentityService.getIdentityCredentials(CLIENT_SESSION_ID))
                .thenReturn(Optional.empty());
        when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(getOrchClientSession()));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertThat(
                result,
                hasBody(
                        objectMapper.writeValueAsString(
                                new IdentityProgressResponse(
                                        IdentityProgressStatus.NO_ENTRY,
                                        CLIENT_NAME,
                                        REDIRECT_URI,
                                        STATE))));
        assertThat(session.getProcessingIdentityAttempts(), equalTo(0));
        assertThat(orchSession.getProcessingIdentityAttempts(), equalTo(0));
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "ProcessingIdentity",
                        Map.of(
                                "Environment",
                                ENVIRONMENT,
                                "Status",
                                IdentityProgressStatus.NO_ENTRY.toString()));

        verify(auditService)
                .submitAuditEvent(IPVAuditableEvent.PROCESSING_IDENTITY_REQUEST, CLIENT_ID, USER);
    }

    @Test
    void shouldReturnExpectedResponseBody() {
        usingValidSession();
        var identityCredentials =
                new OrchIdentityCredentials()
                        .withSubjectID(INTERNAL_COMMON_SUBJECT_ID)
                        .withAdditionalClaims(Collections.emptyMap())
                        .withCoreIdentityJWT("a-core-identity");
        when(dynamoIdentityService.getIdentityCredentials(anyString()))
                .thenReturn(Optional.of(identityCredentials));
        when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(getOrchClientSession()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        Approvals.verify(result.getBody());
    }

    private OrchClientSessionItem getOrchClientSession() {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                responseType, scope, new ClientID(CLIENT_ID), REDIRECT_URI)
                        .state(STATE)
                        .build();

        return new OrchClientSessionItem(
                CLIENT_SESSION_ID, authRequest.toParameters(), null, List.of(), CLIENT_NAME);
    }

    private void usingValidSession() {
        when(sessionService.getSession(anyString())).thenReturn(Optional.of(session));
        when(orchSessionService.getSession(anyString())).thenReturn(Optional.of(orchSession));
    }
}
