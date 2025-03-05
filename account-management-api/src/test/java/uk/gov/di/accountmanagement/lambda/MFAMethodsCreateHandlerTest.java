package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.accountmanagement.helpers.AuditHelper;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.Map;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.identityWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class MFAMethodsCreateHandlerTest {
    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(MFAMethodsCreateHandler.class);

    private final Context context = mock(Context.class);
    private static final String PERSISTENT_ID = "some-persistent-session-id";
    private static final String SESSION_ID = "some-session-id";
    private static final String TXMA_ENCODED_HEADER_VALUE = "txma-test-value";
    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);

    private MFAMethodsCreateHandler handler;

    @BeforeEach
    void setUp() {
        when(configurationService.getEnvironment()).thenReturn("test");
        handler = new MFAMethodsCreateHandler(configurationService);
    }

    @Test
    void shouldReturn200WhenAndHelloWorld() {
        var event = generateApiGatewayEvent("Hello World");

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertEquals("{\"mfaMethod\": \"Hello World\" }", result.getBody());
    }

    @ParameterizedTest
    @ValueSource(strings = {"production", "integration"})
    void shouldReturn400IfRequestIsMadeInProductionOrIntegration(String environment) {
        when(configurationService.getEnvironment()).thenReturn(environment);
        handler = new MFAMethodsCreateHandler(configurationService);

        var event = generateApiGatewayEvent("say hello");

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
    }

    @Test
    void shouldReturn400WhenPathParameterIsIncorrect() {
        var event = generateApiGatewayEvent("Hello World");
        event.setPathParameters(Map.of());

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "Subject missing from request prevents request being handled.")));
    }

    @Test
    void shouldReturn400WhenJsonIsInvalid() {
        var event = generateApiGatewayEvent("Hello World");
        event.setBody("Invalid JSON");

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    private APIGatewayProxyRequestEvent generateApiGatewayEvent(String mfaMethod) {
        var event = new APIGatewayProxyRequestEvent();

        event.setPathParameters(Map.of("publicSubjectId", "helloPath"));
        event.setBody(format("{\"mfaMethod\": \"%s\" }", mfaMethod));
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        proxyRequestContext.setIdentity(identityWithSourceIp("123.123.123.123"));
        event.setRequestContext(proxyRequestContext);
        event.setHeaders(
                Map.of(
                        PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                        PERSISTENT_ID,
                        ClientSessionIdHelper.SESSION_ID_HEADER_NAME,
                        SESSION_ID,
                        AuditHelper.TXMA_ENCODED_HEADER_NAME,
                        TXMA_ENCODED_HEADER_VALUE));

        return event;
    }
}
