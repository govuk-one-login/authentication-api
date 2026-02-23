package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysCreateServiceFailureReason;
import uk.gov.di.authentication.accountdata.helpers.CommonTestVariables;
import uk.gov.di.authentication.accountdata.services.PasskeysCreateService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.CREDENTIAL;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PASSKEY_TRANSPORTS;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PRIMARY_PASSKEY_ID;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.TEST_AAGUID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class PasskeysCreateHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final PasskeysCreateService passkeysCreateService = mock(PasskeysCreateService.class);
    private final Json objectMapper = SerializationService.getInstance();

    private PasskeysCreateHandler handler;

    @BeforeEach
    void setUp() {
        handler = new PasskeysCreateHandler(configurationService, passkeysCreateService);
    }

    @Nested
    class Success {

        @Test
        void shouldReturn200ForValidRequest() throws Json.JsonException {
            // Given
            var pathParams = Map.of("publicSubjectId", CommonTestVariables.PUBLIC_SUBJECT_ID);
            var passkeysCreateRequestBody =
                    buildPasskeysCreateRequestBody(
                            CREDENTIAL,
                            PRIMARY_PASSKEY_ID,
                            TEST_AAGUID,
                            false,
                            0,
                            PASSKEY_TRANSPORTS,
                            false,
                            false,
                            false);
            when(passkeysCreateService.createPasskey(
                            any(), eq(CommonTestVariables.PUBLIC_SUBJECT_ID)))
                    .thenReturn(Result.success(null));

            // When
            var result =
                    handler.handleRequest(
                            passkeysCreateRequest(passkeysCreateRequestBody, pathParams), context);

            // Then
            assertThat(result, hasStatus(201));
        }
    }

    @Nested
    class Error {

        @Test
        void shouldReturn400WhenReadValueFails() throws Json.JsonException {
            // Given
            var pathParams = Map.of("publicSubjectId", CommonTestVariables.PUBLIC_SUBJECT_ID);
            var passkeysCreateRequestBody =
                    buildPasskeysCreateRequestBody(
                            CREDENTIAL,
                            null,
                            TEST_AAGUID,
                            false,
                            0,
                            PASSKEY_TRANSPORTS,
                            false,
                            false,
                            false);

            // When
            var result =
                    handler.handleRequest(
                            passkeysCreateRequest(passkeysCreateRequestBody, pathParams), context);

            // Then
            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.REQUEST_MISSING_PARAMS));
        }

        @Test
        void shouldReturn400WhenPublicSubjectIdIsEmpty() throws Json.JsonException {
            // Given
            var pathParams = Map.of("publicSubjectId", "");
            var passkeysCreateRequestBody =
                    buildPasskeysCreateRequestBody(
                            CREDENTIAL,
                            PRIMARY_PASSKEY_ID,
                            TEST_AAGUID,
                            false,
                            0,
                            PASSKEY_TRANSPORTS,
                            false,
                            false,
                            false);

            // When
            var result =
                    handler.handleRequest(
                            passkeysCreateRequest(passkeysCreateRequestBody, pathParams), context);

            // Then
            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.REQUEST_MISSING_PARAMS));
        }

        @Test
        void shouldReturn500WhenFailedToSavePasskey() throws Json.JsonException {
            // Given
            var pathParams = Map.of("publicSubjectId", CommonTestVariables.PUBLIC_SUBJECT_ID);
            var passkeysCreateRequestBody =
                    buildPasskeysCreateRequestBody(
                            CREDENTIAL,
                            PRIMARY_PASSKEY_ID,
                            TEST_AAGUID,
                            false,
                            0,
                            PASSKEY_TRANSPORTS,
                            false,
                            false,
                            false);
            when(passkeysCreateService.createPasskey(
                            any(), eq(CommonTestVariables.PUBLIC_SUBJECT_ID)))
                    .thenReturn(
                            Result.failure(
                                    PasskeysCreateServiceFailureReason.FAILED_TO_SAVE_PASSKEY));

            // When
            var result =
                    handler.handleRequest(
                            passkeysCreateRequest(passkeysCreateRequestBody, pathParams), context);

            // Then
            assertThat(result, hasStatus(500));
            assertThat(result, hasJsonBody(ErrorResponse.UNEXPECTED_ACCOUNT_DATA_API_ERROR));
        }

        @Test
        void shouldReturn409WhenPasskeyExists() throws Json.JsonException {
            // Given
            var pathParams = Map.of("publicSubjectId", CommonTestVariables.PUBLIC_SUBJECT_ID);
            var passkeysCreateRequestBody =
                    buildPasskeysCreateRequestBody(
                            CREDENTIAL,
                            PRIMARY_PASSKEY_ID,
                            TEST_AAGUID,
                            false,
                            0,
                            PASSKEY_TRANSPORTS,
                            false,
                            false,
                            false);
            when(passkeysCreateService.createPasskey(
                            any(), eq(CommonTestVariables.PUBLIC_SUBJECT_ID)))
                    .thenReturn(Result.failure(PasskeysCreateServiceFailureReason.PASSKEY_EXISTS));

            // When
            var result =
                    handler.handleRequest(
                            passkeysCreateRequest(passkeysCreateRequestBody, pathParams), context);

            // Then
            assertThat(result, hasStatus(409));
            assertThat(result, hasJsonBody(ErrorResponse.PASSKEY_ALREADY_EXISTS));
        }

        @Test
        void shouldReturn422WhenInvalidAaguid() throws Json.JsonException {
            // Given
            var pathParams = Map.of("publicSubjectId", CommonTestVariables.PUBLIC_SUBJECT_ID);
            var passkeysCreateRequestBody =
                    buildPasskeysCreateRequestBody(
                            CREDENTIAL,
                            PRIMARY_PASSKEY_ID,
                            "invalid-aaguid",
                            false,
                            0,
                            PASSKEY_TRANSPORTS,
                            false,
                            false,
                            false);

            // When
            var result =
                    handler.handleRequest(
                            passkeysCreateRequest(passkeysCreateRequestBody, pathParams), context);

            // Then
            assertThat(result, hasStatus(422));
            assertThat(result, hasJsonBody(ErrorResponse.INVALID_AAGUID));
        }

        @Test
        void shouldReturn422WhenEmptyAaguid() throws Json.JsonException {
            // Given
            var pathParams = Map.of("publicSubjectId", CommonTestVariables.PUBLIC_SUBJECT_ID);
            var passkeysCreateRequestBody =
                    buildPasskeysCreateRequestBody(
                            CREDENTIAL,
                            PRIMARY_PASSKEY_ID,
                            "",
                            false,
                            0,
                            PASSKEY_TRANSPORTS,
                            false,
                            false,
                            false);

            // When
            var result =
                    handler.handleRequest(
                            passkeysCreateRequest(passkeysCreateRequestBody, pathParams), context);

            // Then
            assertThat(result, hasStatus(422));
            assertThat(result, hasJsonBody(ErrorResponse.INVALID_AAGUID));
        }
    }

    private String buildPasskeysCreateRequestBody(
            String credential,
            String id,
            String aaguid,
            boolean isAttested,
            int signCount,
            List<String> transports,
            boolean isBackUpEligible,
            boolean isBackedUp,
            boolean isResidentKey)
            throws Json.JsonException {
        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("credential", credential);
        requestBody.put("id", id);
        requestBody.put("aaguid", aaguid);
        requestBody.put("isAttested", String.valueOf(isAttested));
        requestBody.put("signCount", String.valueOf(signCount));
        requestBody.put("transports", transports);
        requestBody.put("isBackedUpEligible", String.valueOf(isBackUpEligible));
        requestBody.put("isBackedUp", String.valueOf(isBackedUp));
        requestBody.put("isResidentKey", String.valueOf(isResidentKey));

        return objectMapper.writeValueAsString(requestBody);
    }

    private APIGatewayProxyRequestEvent passkeysCreateRequest(
            String requestBody, Map<String, String> pathParams) {
        return new APIGatewayProxyRequestEvent()
                .withPathParameters(pathParams)
                .withHeaders(VALID_HEADERS)
                .withBody(requestBody)
                .withRequestContext(contextWithSourceIp(CommonTestVariables.IP_ADDRESS));
    }
}
