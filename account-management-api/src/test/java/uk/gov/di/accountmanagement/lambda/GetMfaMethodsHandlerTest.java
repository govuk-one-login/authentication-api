package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class GetMfaMethodsHandlerTest {
    private final Context context = mock(Context.class);
    private static final String SUBJECT_ID = "some-subject-id";
    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);

    private GetMfaMethodsHandler handler;

    @BeforeEach
    void setUp() {
        handler = new GetMfaMethodsHandler(configurationService);
    }

    @Test
    void shouldReturn200AndDummyResponse() {
        when(configurationService.getEnvironment()).thenReturn("test-environment");
        var event =
                new APIGatewayProxyRequestEvent()
                        .withPathParameters((Map.of("publicSubjectId", SUBJECT_ID)))
                        .withHeaders(VALID_HEADERS);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertEquals("{\"hello\": \"world\"}", result.getBody());
    }

    @Test
    void shouldReturn400IfPublicSubjectIdNotIncludedInPath() {
        when(configurationService.getEnvironment()).thenReturn("test-environment");
        var event =
                new APIGatewayProxyRequestEvent()
                        .withPathParameters((Map.of("publicSubjectId", "")))
                        .withHeaders(VALID_HEADERS);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
    }

    @ParameterizedTest
    @ValueSource(strings = {"production", "integration"})
    void shouldReturn400IfRequestIsMadeInProductionOrIntegration(String environment) {
        when(configurationService.getEnvironment()).thenReturn(environment);
        var event =
                new APIGatewayProxyRequestEvent()
                        .withPathParameters((Map.of("publicSubjectId", SUBJECT_ID)))
                        .withHeaders(VALID_HEADERS);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
    }

    @Test
    void shouldReturn404IfPublicSubjectIdNotFound() {
        when(configurationService.getEnvironment()).thenReturn("test-environment");
        var event =
                new APIGatewayProxyRequestEvent()
                        .withPathParameters(
                                (Map.of("publicSubjectId", "unknown-public-subject-id")))
                        .withHeaders(VALID_HEADERS);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(404));
    }
}
