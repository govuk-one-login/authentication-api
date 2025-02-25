package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class GetMfaMethodsHandlerTest {
    private final Context context = mock(Context.class);
    private static final String SUBJECT_ID = "some-subject-id";

    private GetMfaMethodsHandler handler;

    @BeforeEach
    void setUp() {
        handler = new GetMfaMethodsHandler();
    }

    @Test
    void shouldReturn200AndDummyResponse() {
        var event =
                new APIGatewayProxyRequestEvent()
                        .withPathParameters((Map.of("publicSubjectId", SUBJECT_ID)))
                        .withHeaders(VALID_HEADERS);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertEquals("{\"hello\": \"world\"}", result.getBody());
    }
}
