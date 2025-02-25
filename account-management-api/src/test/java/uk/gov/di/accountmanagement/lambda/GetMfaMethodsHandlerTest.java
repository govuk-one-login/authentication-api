package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.helpers.AuditHelper;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;

import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class GetMfaMethodsHandlerTest {
    private final Context context = mock(Context.class);
    private static final String PERSISTENT_ID = "some-persistent-session-id";
    private static final String SESSION_ID = "some-session-id";
    private static final String TXMA_ENCODED_HEADER_VALUE = "txma-test-value";
    private static final String SUBJECT_ID = "some-subject-id";
    private static final Map<String, String> VALID_HEADERS =
            Map.of(
                    PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                    PERSISTENT_ID,
                    ClientSessionIdHelper.SESSION_ID_HEADER_NAME,
                    SESSION_ID,
                    AuditHelper.TXMA_ENCODED_HEADER_NAME,
                    TXMA_ENCODED_HEADER_VALUE);

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
