package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.services.AuthenticationService;

import java.util.HashMap;
import java.util.Map;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class RemoveAccountHandlerTest {

    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final Subject SUBJECT = new Subject();
    private RemoveAccountHandler handler;
    private final Context context = mock(Context.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);

    @BeforeEach
    public void setUp() {
        handler = new RemoveAccountHandler(authenticationService);
    }

    @Test
    public void shouldReturn200IfAccountRemovalIsSuccessful() {
        when(authenticationService.getSubjectFromEmail(EMAIL)).thenReturn(SUBJECT);
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

        assertThat(result, hasStatus(200));
    }

    @Test
    public void shouldReturn400WhenAccountDoesNotExist() {
        when(authenticationService.getSubjectFromEmail(EMAIL)).thenReturn(SUBJECT);
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", SUBJECT.getValue());
        proxyRequestContext.setAuthorizer(authorizerParams);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(proxyRequestContext);
        event.setBody(format("{ \"email\": \"%s\" }", EMAIL));

        when(authenticationService.userExists(EMAIL)).thenReturn(false);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);
        verify(authenticationService, never()).removeAccount(eq(EMAIL));

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1010));
    }
}
