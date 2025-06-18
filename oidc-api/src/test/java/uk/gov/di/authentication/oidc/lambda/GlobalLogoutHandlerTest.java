package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.oidc.entity.GlobalLogoutMessage;

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
                                "Missing required fields",
                                new GlobalLogoutMessage(null, null, null, null, null, null, null))),
                Arguments.of(
                        Named.of(
                                "Fields are empty strings",
                                new GlobalLogoutMessage("", "", "", "", "", "", ""))),
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
