package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.util.HashMap;
import java.util.Map;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class UpdatePasswordHandlerTest {

    private final Context context = mock(Context.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private UpdatePasswordHandler handler;
    private static final String EXISTING_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String NEW_PASSWORD = "password2";
    private static final Subject SUBJECT = new Subject();

    @BeforeEach
    public void setUp() {
        handler = new UpdatePasswordHandler(dynamoService);
    }

    @Test
    public void shouldReturn200ForValidRequest() {
        when(dynamoService.getSubjectFromEmail(EXISTING_EMAIL_ADDRESS)).thenReturn(SUBJECT);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"newPassword\": \"%s\" }",
                        EXISTING_EMAIL_ADDRESS, NEW_PASSWORD));
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", SUBJECT.getValue());
        proxyRequestContext.setAuthorizer(authorizerParams);
        event.setRequestContext(proxyRequestContext);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        verify(dynamoService).updatePassword(EXISTING_EMAIL_ADDRESS, NEW_PASSWORD);
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
    }
}
