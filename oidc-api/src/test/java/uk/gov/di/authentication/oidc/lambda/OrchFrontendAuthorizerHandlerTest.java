package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.entity.AuthPolicy;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.helper.RequestEventHelper.contextWithSourceIp;

class OrchFrontendAuthorizerHandlerTest {
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private OrchFrontendAuthorizerHandler handler;
    private final Context context = mock(Context.class);
    private static final String NON_PROD_ENV = "test-environment";
    private static final String REQUEST_ID = "test-request-id";
    private static final String RESOURCE = "test-resource";
    private static final String TRUSTED_IP = "51.149.8.89";
    private static final String NON_TRUSTED_IP = "41.149.8.89";

    @BeforeEach
    public void setup() {
        handler = new OrchFrontendAuthorizerHandler(configurationService);
        when(context.getAwsRequestId()).thenReturn(REQUEST_ID);
    }

    @Test
    public void shouldReturnAuthPolicyForAllowedIpAddress() {
        when(configurationService.getEnvironment()).thenReturn(NON_PROD_ENV);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp(TRUSTED_IP));
        event.setResource(RESOURCE);

        AuthPolicy authPolicy = handler.handleRequest(event, context);

        assertThat(authPolicy.getPrincipalId(), equalTo(REQUEST_ID));
        assertNotNull(authPolicy.getPolicyDocument().get("Statement"));
    }

    @Test
    public void shouldThrowExceptionForNotAllowedIpAddress() {
        when(configurationService.getEnvironment()).thenReturn(NON_PROD_ENV);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp(NON_TRUSTED_IP));
        event.setResource(RESOURCE);

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        assertEquals("Unauthorized", exception.getMessage());
    }

    @Test
    public void shouldReturnAuthPolicyInProductionEnvironment() {
        when(configurationService.getEnvironment()).thenReturn("production");
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp(NON_TRUSTED_IP));
        event.setResource(RESOURCE);

        AuthPolicy authPolicy = handler.handleRequest(event, context);

        assertThat(authPolicy.getPrincipalId(), equalTo(REQUEST_ID));
        assertNotNull(authPolicy.getPolicyDocument().get("Statement"));
    }

    @Test
    public void shouldReturnAuthPolicyInIntegrationEnvironment() {
        when(configurationService.getEnvironment()).thenReturn("integration");
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp(NON_TRUSTED_IP));
        event.setResource(RESOURCE);

        AuthPolicy authPolicy = handler.handleRequest(event, context);

        assertThat(authPolicy.getPrincipalId(), equalTo(REQUEST_ID));
        assertNotNull(authPolicy.getPolicyDocument().get("Statement"));
    }
}
