package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.accountdata.services.ConfigurationService;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.accountdata.helpers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AccountDeleteHandlerTest {
    private static final String TEST_PUBLIC_SUBJECT = new Subject().getValue();
    private static final UserProfile TEST_USER_PROFILE =
            new UserProfile().withPublicSubjectID(TEST_PUBLIC_SUBJECT);
    private static final String PUBLIC_SUBJECT_ID_KEY = "publicSubjectId";

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);

    private final Context context = mock(Context.class);
    private final AccountDeleteHandler handler =
            new AccountDeleteHandler(configurationService, dynamoService);

    @Test
    void shouldReturn204() {
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(TEST_USER_PROFILE));

        var request =
                new APIGatewayProxyRequestEvent()
                        .withPathParameters(Map.of(PUBLIC_SUBJECT_ID_KEY, TEST_PUBLIC_SUBJECT));

        var result = handler.handleRequest(request, context);

        assertThat(result, hasStatus(204));
    }

    @Test
    void shouldReturn404WhenUserProfileNotFoundForPublicSubject() {
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.empty());

        var request =
                new APIGatewayProxyRequestEvent()
                        .withPathParameters(Map.of(PUBLIC_SUBJECT_ID_KEY, TEST_PUBLIC_SUBJECT));

        var result = handler.handleRequest(request, context);

        assertEquals(
                "{\"code\":1056,\"message\":\"User not found or no match\"}", result.getBody());
        assertThat(result, hasStatus(404));
    }

    private static Stream<Map<String, String>> invalidPathParameters() {
        return Stream.of(Map.of("publicSubjectId", ""), Map.of());
    }

    @ParameterizedTest
    @MethodSource("invalidPathParameters")
    void shouldReturn400IfPathParameterIsInvalid(Map<String, String> pathParameters) {
        var request = new APIGatewayProxyRequestEvent().withPathParameters(pathParameters);

        var result = handler.handleRequest(request, context);

        assertEquals(
                "{\"code\":1001,\"message\":\"Request is missing parameters\"}", result.getBody());
        assertThat(result, hasStatus(400));
    }
}
