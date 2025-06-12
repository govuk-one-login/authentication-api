package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Map;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static uk.gov.di.orchestration.sharedtest.helper.SqsTestHelper.sqsEventWithPayload;

public class GlobalLogoutHandlerTest {
    private final Context context = mock(Context.class);
    private final GlobalLogoutHandler globalLogoutHandler = new GlobalLogoutHandler();

    private static Stream<Arguments> invalidMessages() {
        return Stream.of(
                Arguments.of(
                        Named.of(
                                "Missing internal_common_subject_id",
                                Map.ofEntries(
                                        Map.entry("session_id", "sid"),
                                        Map.entry("client_session_id", "csid")))),
                Arguments.of(
                        Named.of(
                                "Missing session_id",
                                Map.ofEntries(
                                        Map.entry("internal_common_subject_id", "icsid"),
                                        Map.entry("client_session_id", "csid")))),
                Arguments.of(
                        Named.of(
                                "Missing client_session_id",
                                Map.ofEntries(
                                        Map.entry("session_id", "sid"),
                                        Map.entry("internal_common_subject_id", "icsid")))),
                Arguments.of(Named.of("Invalid JSON", "{")));
    }

    @ParameterizedTest
    @MethodSource("invalidMessages")
    void shouldRejectInvalidMessage(Object payload) {
        var input = sqsEventWithPayload("test-message-id", payload);

        var response = globalLogoutHandler.handleRequest(input, context);

        assertThat(response, equalTo(failedMessages("test-message-id")));
    }

    private SQSBatchResponse failedMessages(String... messageIds) {
        return new SQSBatchResponse(
                Stream.of(messageIds).map(SQSBatchResponse.BatchItemFailure::new).toList());
    }
}
