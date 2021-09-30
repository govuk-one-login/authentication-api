package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuthenticationService;

import java.util.HashMap;
import java.util.Map;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.entity.NotificationType.DELETE_ACCOUNT;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class RemoveAccountHandlerTest {

    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final Subject SUBJECT = new Subject();
    private RemoveAccountHandler handler;
    private final Context context = mock(Context.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);

    @BeforeEach
    public void setUp() {
        handler = new RemoveAccountHandler(authenticationService, sqsClient);
    }

    @Test
    public void shouldReturn204IfAccountRemovalIsSuccessful() throws JsonProcessingException {
        UserProfile userProfile = new UserProfile().setPublicSubjectID(SUBJECT.getValue());
        when(authenticationService.getUserProfileByEmail(EMAIL)).thenReturn(userProfile);
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", SUBJECT.getValue());
        proxyRequestContext.setAuthorizer(authorizerParams);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(proxyRequestContext);
        event.setBody(format("{ \"email\": \"%s\" }", EMAIL));

        when(authenticationService.userExists(EMAIL)).thenReturn(true);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);
        verify(authenticationService).removeAccount(eq(EMAIL));
        NotifyRequest notifyRequest = new NotifyRequest(EMAIL, DELETE_ACCOUNT);
        verify(sqsClient).send(new ObjectMapper().writeValueAsString(notifyRequest));

        assertThat(result, hasStatus(204));
    }
}
