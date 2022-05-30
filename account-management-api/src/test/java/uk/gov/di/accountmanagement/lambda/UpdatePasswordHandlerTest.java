package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.Argon2EncoderHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.HashMap;
import java.util.Map;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.identityWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class UpdatePasswordHandlerTest {

    private final Context context = mock(Context.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private final AuditService auditService = mock(AuditService.class);

    private UpdatePasswordHandler handler;
    private static final String EXISTING_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String NEW_PASSWORD = "password2";
    private static final String CURRENT_PASSWORD = "password1";
    private static final Subject SUBJECT = new Subject();
    private final Json objectMapper = SerializationService.getInstance();

    @BeforeEach
    public void setUp() {
        handler = new UpdatePasswordHandler(dynamoService, sqsClient, auditService);
    }

    @Test
    public void shouldReturn204ForValidRequest() throws Json.JsonException {
        String persistentIdValue = "some-persistent-session-id";
        UserProfile userProfile = new UserProfile().setPublicSubjectID(SUBJECT.getValue());
        UserCredentials userCredentials = new UserCredentials().setPassword(CURRENT_PASSWORD);
        when(dynamoService.getUserProfileByEmail(EXISTING_EMAIL_ADDRESS)).thenReturn(userProfile);
        when(dynamoService.getUserCredentialsFromEmail(EXISTING_EMAIL_ADDRESS))
                .thenReturn(userCredentials);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"newPassword\": \"%s\" }",
                        EXISTING_EMAIL_ADDRESS, NEW_PASSWORD));
        event.setHeaders(Map.of(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, persistentIdValue));
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", SUBJECT.getValue());
        proxyRequestContext.setIdentity(identityWithSourceIp("123.123.123.123"));
        proxyRequestContext.setAuthorizer(authorizerParams);
        event.setRequestContext(proxyRequestContext);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(dynamoService).updatePassword(EXISTING_EMAIL_ADDRESS, NEW_PASSWORD);
        NotifyRequest notifyRequest =
                new NotifyRequest(EXISTING_EMAIL_ADDRESS, NotificationType.PASSWORD_UPDATED);
        verify(sqsClient).send(objectMapper.writeValueAsString(notifyRequest));

        verify(auditService)
                .submitAuditEvent(
                        AccountManagementAuditableEvent.UPDATE_PASSWORD,
                        context.getAwsRequestId(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        userProfile.getSubjectID(),
                        userProfile.getEmail(),
                        "123.123.123.123",
                        userProfile.getPhoneNumber(),
                        persistentIdValue);
    }

    @Test
    public void shouldReturn400WhenRequestHasIncorrectParameters() {
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", SUBJECT.getValue());
        proxyRequestContext.setAuthorizer(authorizerParams);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(proxyRequestContext);
        event.setBody(
                format("{ \"incorrect\": \"%s\", \"parameter\": \"%s\"}", "incorrect", "value"));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));

        verifyNoInteractions(auditService);
    }

    @Test
    public void shouldReturn400WhenNewPasswordEqualsExistingPassword() throws Json.JsonException {
        UserProfile userProfile = new UserProfile().setPublicSubjectID(SUBJECT.getValue());
        UserCredentials userCredentials =
                new UserCredentials().setPassword(Argon2EncoderHelper.argon2Hash(NEW_PASSWORD));
        when(dynamoService.getUserProfileByEmail(EXISTING_EMAIL_ADDRESS)).thenReturn(userProfile);
        when(dynamoService.getUserCredentialsFromEmail(EXISTING_EMAIL_ADDRESS))
                .thenReturn(userCredentials);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"newPassword\": \"%s\" }",
                        EXISTING_EMAIL_ADDRESS, NEW_PASSWORD));
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", SUBJECT.getValue());
        proxyRequestContext.setIdentity(identityWithSourceIp("123.123.123.123"));
        proxyRequestContext.setAuthorizer(authorizerParams);
        event.setRequestContext(proxyRequestContext);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1024));
        verify(dynamoService, never()).updatePassword(EXISTING_EMAIL_ADDRESS, NEW_PASSWORD);
        NotifyRequest notifyRequest =
                new NotifyRequest(EXISTING_EMAIL_ADDRESS, NotificationType.PASSWORD_UPDATED);
        verify(sqsClient, never()).send(objectMapper.writeValueAsString(notifyRequest));

        verify(auditService, never())
                .submitAuditEvent(
                        AccountManagementAuditableEvent.UPDATE_PASSWORD,
                        context.getAwsRequestId(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        userProfile.getSubjectID(),
                        userProfile.getEmail(),
                        "123.123.123.123",
                        userProfile.getPhoneNumber(),
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE);
    }
}
