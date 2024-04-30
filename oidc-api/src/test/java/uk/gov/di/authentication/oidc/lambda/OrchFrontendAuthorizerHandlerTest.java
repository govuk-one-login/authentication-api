package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.helper.RequestEventHelper.identityWithSourceIp;

class OrchFrontendAuthorizerHandlerTest {
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private OrchFrontendAuthorizerHandler handler;
    private final Context context = mock(Context.class);
    APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
    private static final String NON_PROD_ENV = "test-environment";
    private static final String REGION = "eu-west-2";
    private static final String REQUEST_ID = "test-request-id";
    private static final String ACCOUNT_ID = "123456789012";
    private static final String STAGE = "test-invoke-stage";
    private static final String API_ID = "abcdef123";
    private static final String TRUSTED_IP = "51.149.8.89";
    private static final String NON_TRUSTED_IP = "41.149.8.89";

    private static final String ALLOW_POLICY =
            "{policyDocument={Version=2012-10-17, Statement={Action=execute-api:Invoke, Resource=arn:aws:execute-api:eu-west-2:123456789012:abcdef123/test-invoke-stage/*/orch-frontend/*, Effect=Allow}}, principalId=test-request-id}";

    @BeforeEach
    public void setup() {
        handler = new OrchFrontendAuthorizerHandler(configurationService);
        when(context.getAwsRequestId()).thenReturn(REQUEST_ID);
        when(configurationService.getAwsRegion()).thenReturn(REGION);
    }

    @Test
    public void shouldReturnAuthPolicyForAllowedIpAddress() {
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext()
                        .withAccountId(ACCOUNT_ID)
                        .withStage(STAGE)
                        .withApiId(API_ID)
                        .withIdentity(identityWithSourceIp(TRUSTED_IP));
        event.setRequestContext(proxyRequestContext);
        when(configurationService.getEnvironment()).thenReturn(NON_PROD_ENV);

        Map<String, Object> policy = handler.handleRequest(event, context);

        assertThat(policy.toString(), equalTo(ALLOW_POLICY));
    }

    @Test
    public void shouldThrowExceptionForNotAllowedIpAddress() {
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext()
                        .withAccountId(ACCOUNT_ID)
                        .withStage(STAGE)
                        .withApiId(API_ID)
                        .withIdentity(identityWithSourceIp(NON_TRUSTED_IP));
        event.setRequestContext(proxyRequestContext);
        when(configurationService.getEnvironment()).thenReturn(NON_PROD_ENV);

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        assertEquals("Unauthorized", exception.getMessage());
    }

    @Test
    public void shouldReturnAuthPolicyInProductionEnvironment() {
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext()
                        .withAccountId(ACCOUNT_ID)
                        .withStage(STAGE)
                        .withApiId(API_ID)
                        .withIdentity(identityWithSourceIp(NON_TRUSTED_IP));
        event.setRequestContext(proxyRequestContext);
        when(configurationService.getEnvironment()).thenReturn("production");

        Map<String, Object> policy = handler.handleRequest(event, context);

        assertThat(policy.toString(), equalTo(ALLOW_POLICY));
    }

    @Test
    public void shouldReturnAuthPolicyInIntegrationEnvironment() {
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext()
                        .withAccountId(ACCOUNT_ID)
                        .withStage(STAGE)
                        .withApiId(API_ID)
                        .withIdentity(identityWithSourceIp(NON_TRUSTED_IP));
        event.setRequestContext(proxyRequestContext);
        when(configurationService.getEnvironment()).thenReturn("integration");

        Map<String, Object> policy = handler.handleRequest(event, context);

        assertThat(policy.toString(), equalTo(ALLOW_POLICY));
    }
}
