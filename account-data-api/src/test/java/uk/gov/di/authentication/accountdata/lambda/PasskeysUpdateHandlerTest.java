package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.accountdata.entity.passkey.Passkey;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysUpdateFailureReason;
import uk.gov.di.authentication.accountdata.services.PasskeysService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.Map;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.accountdata.helpers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.accountdata.helpers.APIGatewayProxyResponseEventMatcher.hasStatus;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.LAST_USED_AT;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PRIMARY_PASSKEY_ID;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PUBLIC_SUBJECT_ID;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.SIGN_COUNT;
import static uk.gov.di.authentication.accountdata.helpers.RequestHelper.contextWithSourceIp;

class PasskeysUpdateHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final PasskeysService passkeysService = mock(PasskeysService.class);

    private PasskeysUpdateHandler handler;

    @BeforeEach
    void setUp() {
        handler =
                new PasskeysUpdateHandler(
                        configurationService, SerializationService.getInstance(), passkeysService);
    }

    @Nested
    class Success {
        @Test
        void shouldReturn204ForValidRequest() {
            // Given
            var request =
                    passkeysUpdateRequest(
                            SIGN_COUNT, LAST_USED_AT, PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID);
            when(passkeysService.updatePasskey(any(), any(), any(), anyInt()))
                    .thenReturn(Result.success(new Passkey()));

            // When
            var result = handler.handleRequest(request, context);

            // Then
            verify(passkeysService)
                    .updatePasskey(PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID, LAST_USED_AT, SIGN_COUNT);
            assertThat(result, hasStatus(204));
        }
    }

    @Nested
    class Error {
        @Test
        void shouldReturn404WhenPasskeyDoesNotExist() {
            // Given
            var request =
                    passkeysUpdateRequest(
                            SIGN_COUNT, LAST_USED_AT, PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID);
            when(passkeysService.updatePasskey(any(), any(), any(), anyInt()))
                    .thenReturn(Result.failure(PasskeysUpdateFailureReason.PASSKEY_NOT_FOUND));

            // When
            var result = handler.handleRequest(request, context);

            // Then
            assertThat(result, hasStatus(404));
            assertThat(result, hasJsonBody(ErrorResponse.PASSKEY_NOT_FOUND));
        }

        @Test
        void shouldReturn500WhenDatabaseOperationFails() {
            // Given
            var request =
                    passkeysUpdateRequest(
                            SIGN_COUNT, LAST_USED_AT, PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID);
            when(passkeysService.updatePasskey(any(), any(), any(), anyInt()))
                    .thenReturn(
                            Result.failure(PasskeysUpdateFailureReason.FAILED_TO_UPDATE_PASSKEY));
            // When
            var result = handler.handleRequest(request, context);

            // Then
            assertThat(result, hasStatus(500));
            assertThat(result, hasJsonBody(ErrorResponse.INTERNAL_SERVER_ERROR));
        }

        private static Stream<String> invalidRequestBodies() {
            var validTimestamp = "2026-03-02T16:01:45";
            return Stream.of(
                    "invalidBody",
                    //                    sign_count instead of signCount
                    "{\"sign_count\":5,\"lastUsedAt\":\"%s\"}".formatted(validTimestamp),
                    //                    missing signCount
                    "{\"lastUsedAt\":\"%s\"}".formatted(validTimestamp),
                    //                    missing lastUsedAt
                    "{\"signCount\":5}",
                    // invalid sign count type
                    "{\"signCount\":\"not an int\",\"lastUsedAt\":\"%s\"}"
                            .formatted(validTimestamp),
                    // invalid time date format
                    "{\"signCount\":1,\"lastUsedAt\":\"not-a-timestamp\"}");
        }

        @ParameterizedTest
        @MethodSource("invalidRequestBodies")
        void shouldReturn400WhenRequestBodyIsInvalid(String invalidRequestBody) {
            // Given
            var request =
                    baseApiProxyRequest()
                            .withPathParameters(
                                    Map.ofEntries(
                                            Map.entry("publicSubjectId", PUBLIC_SUBJECT_ID),
                                            Map.entry("passkeyId", PRIMARY_PASSKEY_ID)))
                            .withBody(invalidRequestBody);

            // When
            var result = handler.handleRequest(request, context);

            // Then
            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.INVALID_REQUEST_BODY));
        }

        @Test
        void shouldReturn400WhenRequestIsMissingPublicSubjectId() {
            // Given
            var requestBody =
                    "{\"signCount\":%d, \"lastUsedAt\":\"%s\"}".formatted(SIGN_COUNT, LAST_USED_AT);
            var pathParamsWithoutPublicSubject =
                    Map.ofEntries(Map.entry("passkeyId", PRIMARY_PASSKEY_ID));
            var request =
                    baseApiProxyRequest()
                            .withPathParameters(pathParamsWithoutPublicSubject)
                            .withBody(requestBody);

            // When
            var result = handler.handleRequest(request, context);

            // Then
            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.MISSING_SUBJECT_ID));
        }

        @Test
        void shouldReturn400WhenRequestIsMissingPasskeyId() {
            // Given
            var requestBody =
                    "{\"signCount\":%d, \"lastUsedAt\":\"%s\"}".formatted(SIGN_COUNT, LAST_USED_AT);
            var pathParamsWithoutPublicSubject =
                    Map.ofEntries(Map.entry("publicSubjectId", PUBLIC_SUBJECT_ID));
            var request =
                    baseApiProxyRequest()
                            .withPathParameters(pathParamsWithoutPublicSubject)
                            .withBody(requestBody);

            // When
            var result = handler.handleRequest(request, context);

            // Then
            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.MISSING_PASSKEY_ID));
        }
    }

    private APIGatewayProxyRequestEvent passkeysUpdateRequest(
            int signCount, String lastUsed, String publicSubjectId, String passkeyId) {
        return baseApiProxyRequest()
                .withPathParameters(
                        Map.of("publicSubjectId", publicSubjectId, "passkeyId", passkeyId))
                .withBody(
                        "{\"signCount\":%d, \"lastUsedAt\":\"%s\"}".formatted(signCount, lastUsed));
    }

    private APIGatewayProxyRequestEvent baseApiProxyRequest() {
        return new APIGatewayProxyRequestEvent()
                .withRequestContext(contextWithSourceIp(IP_ADDRESS));
    }
}
