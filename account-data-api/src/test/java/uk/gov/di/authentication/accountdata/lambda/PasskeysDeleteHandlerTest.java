package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static uk.gov.di.authentication.accountdata.helpers.APIGatewayProxyResponseEventMatcher.hasStatus;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PUBLIC_SUBJECT_ID;
import static uk.gov.di.authentication.accountdata.helpers.RequestHelper.contextWithSourceIp;

class PasskeysDeleteHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    private PasskeysDeleteHandler handler;

    @BeforeEach
    void setUp() {
        handler = new PasskeysDeleteHandler(configurationService);
    }

    @Nested
    class Success {
        @Test
        void shouldReturn204ForValidRequest() {
            // Given
            var pathParams = Map.of("publicSubjectId", PUBLIC_SUBJECT_ID);
            var authorizerParams = Map.<String, Object>of("principalId", PUBLIC_SUBJECT_ID);

            // When
            var result =
                    handler.handleRequest(
                            passkeysDeleteRequest(pathParams, authorizerParams), context);

            // Then
            assertThat(result, hasStatus(204));
        }
    }

    @Nested
    class Failure {
        @Test
        void shouldReturn400WhenPublicSubjectIdNotPresent() {
            // Given
            var pathParams = Map.<String, String>of();
            var authorizerParams = Map.<String, Object>of("principalId", PUBLIC_SUBJECT_ID);

            // When
            var result =
                    handler.handleRequest(
                            passkeysDeleteRequest(pathParams, authorizerParams), context);

            // Then
            assertThat(result, hasStatus(400));
        }

        @Test
        void shouldReturn401WhenPublicSubjectIdDoesNotMatchTheOneInAuthorizerParams() {
            // Given
            var pathParams = Map.of("publicSubjectId", PUBLIC_SUBJECT_ID);
            var authorizerParams = Map.<String, Object>of("principalId", "another-subject-id");

            // When
            var result =
                    handler.handleRequest(
                            passkeysDeleteRequest(pathParams, authorizerParams), context);

            // Then
            assertThat(result, hasStatus(401));
        }
    }

    private APIGatewayProxyRequestEvent passkeysDeleteRequest(
            Map<String, String> pathParams, Map<String, Object> authorizerParams) {
        var context = contextWithSourceIp(IP_ADDRESS);
        context.setAuthorizer(authorizerParams);
        return new APIGatewayProxyRequestEvent()
                .withRequestContext(context)
                .withPathParameters(pathParams);
    }
}
