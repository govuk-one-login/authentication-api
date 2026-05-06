package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysDeleteFailureReason;
import uk.gov.di.authentication.accountdata.services.PasskeysService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Map;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.accountdata.helpers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.accountdata.helpers.APIGatewayProxyResponseEventMatcher.hasStatus;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PRIMARY_PASSKEY_ID;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PUBLIC_SUBJECT_ID;
import static uk.gov.di.authentication.accountdata.helpers.RequestHelper.contextWithSourceIp;

class PasskeysDeleteHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final PasskeysService passkeysService = mock(PasskeysService.class);

    private PasskeysDeleteHandler handler;

    @BeforeEach
    void setUp() {
        handler = new PasskeysDeleteHandler(configurationService, passkeysService);
    }

    @Nested
    class Success {
        @Test
        void shouldReturn204WhenPasskeyCanBeDeleted() {
            // Given
            var pathParams =
                    Map.of("publicSubjectId", PUBLIC_SUBJECT_ID, "passkeyId", PRIMARY_PASSKEY_ID);
            var authorizerParams = Map.<String, Object>of("principalId", PUBLIC_SUBJECT_ID);
            when(passkeysService.deletePasskey(PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID))
                    .thenReturn(Result.success(null));

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
        void shouldReturn404WhenPasskeyNotFound() {
            // Given
            var pathParams =
                    Map.of("publicSubjectId", PUBLIC_SUBJECT_ID, "passkeyId", PRIMARY_PASSKEY_ID);
            var authorizerParams = Map.<String, Object>of("principalId", PUBLIC_SUBJECT_ID);
            when(passkeysService.deletePasskey(PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID))
                    .thenReturn(Result.failure(PasskeysDeleteFailureReason.PASSKEY_NOT_FOUND));

            // When
            var result =
                    handler.handleRequest(
                            passkeysDeleteRequest(pathParams, authorizerParams), context);

            // Then
            assertThat(result, hasStatus(404));
            assertThat(result, hasJsonBody(ErrorResponse.PASSKEY_NOT_FOUND));
        }

        @Test
        void shouldReturn500WhenDatabaseOperationFails() {
            // Given
            var pathParams =
                    Map.of("publicSubjectId", PUBLIC_SUBJECT_ID, "passkeyId", PRIMARY_PASSKEY_ID);
            var authorizerParams = Map.<String, Object>of("principalId", PUBLIC_SUBJECT_ID);
            when(passkeysService.deletePasskey(PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID))
                    .thenReturn(
                            Result.failure(PasskeysDeleteFailureReason.FAILED_TO_DELETE_PASSKEY));

            // When
            var result =
                    handler.handleRequest(
                            passkeysDeleteRequest(pathParams, authorizerParams), context);

            // Then
            assertThat(result, hasStatus(500));
            assertThat(result, hasJsonBody(ErrorResponse.INTERNAL_SERVER_ERROR));
        }

        private static Stream<Arguments> pathParamsWithMissingFields() {
            return Stream.of(
                    Arguments.of(
                            Map.of("passkeyId", PRIMARY_PASSKEY_ID),
                            ErrorResponse.MISSING_SUBJECT_ID),
                    Arguments.of(
                            Map.of("publicSubjectId", "", "passkeyId", PRIMARY_PASSKEY_ID),
                            ErrorResponse.MISSING_SUBJECT_ID),
                    Arguments.of(
                            Map.of("publicSubjectId", PUBLIC_SUBJECT_ID),
                            ErrorResponse.MISSING_PASSKEY_ID),
                    Arguments.of(
                            Map.of("publicSubjectId", PUBLIC_SUBJECT_ID, "passkeyId", ""),
                            ErrorResponse.MISSING_PASSKEY_ID));
        }

        @ParameterizedTest
        @MethodSource("pathParamsWithMissingFields")
        void shouldReturn400WhenPathParamsHaveMissingFields(
                Map<String, String> pathParamsWithMissingFields,
                ErrorResponse expectedErrorResponse) {
            // Given
            var authorizerParams = Map.<String, Object>of("principalId", PUBLIC_SUBJECT_ID);

            // When
            var result =
                    handler.handleRequest(
                            passkeysDeleteRequest(pathParamsWithMissingFields, authorizerParams),
                            context);

            // Then
            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(expectedErrorResponse));
        }

        @Test
        void shouldReturn401WhenPublicSubjectIdDoesNotMatchTheOneInAuthorizerParams() {
            // Given
            var pathParams =
                    Map.of("publicSubjectId", PUBLIC_SUBJECT_ID, "passkeyId", PRIMARY_PASSKEY_ID);
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
