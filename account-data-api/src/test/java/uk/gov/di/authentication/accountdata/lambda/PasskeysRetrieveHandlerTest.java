package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.accountdata.entity.passkey.PasskeysRetrieveResponse;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysRetrieveFailureReasons;
import uk.gov.di.authentication.accountdata.helpers.PasskeysTestHelper;
import uk.gov.di.authentication.accountdata.services.PasskeysService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.accountdata.helpers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.accountdata.helpers.APIGatewayProxyResponseEventMatcher.hasStatus;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PRIMARY_PASSKEY_ID;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PUBLIC_SUBJECT_ID;
import static uk.gov.di.authentication.accountdata.helpers.RequestHelper.contextWithSourceIp;

class PasskeysRetrieveHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final PasskeysService passkeysService = mock(PasskeysService.class);
    private static final Map<String, Object> AUTHORIZER_PARAMS =
            Map.of("principalId", PUBLIC_SUBJECT_ID);

    private PasskeysRetrieveHandler handler;

    @BeforeEach
    void setUp() {
        handler = new PasskeysRetrieveHandler(configurationService, passkeysService);
    }

    @Nested
    class Success {

        @Test
        void shouldReturn200ForValidRequest() {
            // Given
            var pathParams = Map.of("publicSubjectId", PUBLIC_SUBJECT_ID);
            var savedPasskey =
                    PasskeysTestHelper.buildGenericPasskeyForUserWithSubjectId(
                            PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID);
            var savedPasskeysForUser = List.of(savedPasskey);
            var expectedRetrievedPasskeys =
                    new PasskeysRetrieveResponse(
                            List.of(PasskeysRetrieveResponse.from(savedPasskey)));

            when(passkeysService.retrievePasskeys(PUBLIC_SUBJECT_ID))
                    .thenReturn(Result.success(savedPasskeysForUser));

            // When
            var result =
                    handler.handleRequest(
                            passkeysRetrieveRequest(pathParams, AUTHORIZER_PARAMS), context);

            // Then
            assertThat(result, hasStatus(200));
            assertThat(result, hasJsonBody(expectedRetrievedPasskeys));
        }
    }

    @Nested
    class Error {

        @Test
        void shouldReturn400ForInvalidRequest() {
            // Given
            var pathParams = Map.of("publicSubjectId", "");

            // When
            var result =
                    handler.handleRequest(
                            passkeysRetrieveRequest(pathParams, AUTHORIZER_PARAMS), context);

            // Then
            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.REQUEST_MISSING_PARAMS));
        }

        @Test
        void shouldReturn401WhenPublicSubjectIdDoesNotMatchTheOneInAuthorizerParams() {
            // Given
            var pathParams = Map.of("publicSubjectId", PUBLIC_SUBJECT_ID);
            var authorizerParams =
                    Map.<String, Object>of("principalId", "a-different-public-subject-id");

            // When
            var result =
                    handler.handleRequest(
                            passkeysRetrieveRequest(pathParams, authorizerParams), context);

            // Then
            assertThat(result, hasStatus(401));
            assertThat(result, hasJsonBody(ErrorResponse.UNAUTHORIZED_REQUEST));
        }

        @Test
        void shouldReturn500IfFailedToGetPasskeys() {
            // Given
            var pathParams = Map.of("publicSubjectId", PUBLIC_SUBJECT_ID);
            when(passkeysService.retrievePasskeys(PUBLIC_SUBJECT_ID))
                    .thenReturn(
                            Result.failure(PasskeysRetrieveFailureReasons.FAILED_TO_GET_PASSKEYS));

            // When
            var result =
                    handler.handleRequest(
                            passkeysRetrieveRequest(pathParams, AUTHORIZER_PARAMS), context);

            // Then
            assertThat(result, hasStatus(500));
            assertThat(result, hasJsonBody(ErrorResponse.INTERNAL_SERVER_ERROR));
        }
    }

    private APIGatewayProxyRequestEvent passkeysRetrieveRequest(
            Map<String, String> pathParams, Map<String, Object> authorizerParams) {
        var requestContext = contextWithSourceIp(IP_ADDRESS);
        requestContext.setAuthorizer(authorizerParams);
        return new APIGatewayProxyRequestEvent()
                .withPathParameters(pathParams)
                .withRequestContext(requestContext);
    }
}
