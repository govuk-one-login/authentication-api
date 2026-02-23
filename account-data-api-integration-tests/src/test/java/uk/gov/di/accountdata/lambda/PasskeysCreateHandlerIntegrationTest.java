package uk.gov.di.accountdata.lambda;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.accountdata.lambda.PasskeysCreateHandler;
import uk.gov.di.authentication.accountdata.services.DynamoPasskeyService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AuthenticatorExtension;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.CREDENTIAL;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PASSKEY_TRANSPORTS;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PRIMARY_PASSKEY_ID;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PUBLIC_SUBJECT_ID;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.TEST_AAGUID;
import static uk.gov.di.authentication.accountdata.helpers.PasskeysTestHelper.buildGenericPasskeyForUserWithSubjectId;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class PasskeysCreateHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    DynamoPasskeyService dynamoPasskeyService =
            new DynamoPasskeyService(TEST_CONFIGURATION_SERVICE);

    @RegisterExtension
    protected static final AuthenticatorExtension authenticatorExtension =
            new AuthenticatorExtension();

    private final Json objectMapper = SerializationService.getInstance();

    @BeforeEach
    void setUp() {
        handler = new PasskeysCreateHandler(TEST_CONFIGURATION_SERVICE);
    }

    @Nested
    class Success {

        @Test
        void shouldCreatePasskey() throws Json.JsonException {
            // Given
            Map<String, String> headers = new HashMap<>();

            var requestBody =
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
            var expectedSortKey = format("PASSKEY#%s", PRIMARY_PASSKEY_ID);

            // When
            var response =
                    makeRequest(
                            Optional.of(requestBody),
                            headers,
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", PUBLIC_SUBJECT_ID));

            // Then
            assertThat(response.getStatusCode(), equalTo(201));

            var savedPasskeysForUser = dynamoPasskeyService.getPasskeysForUser(PUBLIC_SUBJECT_ID);
            var savedPasskey = savedPasskeysForUser.get(0);

            assertThat(savedPasskey.getCredentialId(), equalTo(PRIMARY_PASSKEY_ID));
            assertThat(savedPasskey.getSortKey(), equalTo(expectedSortKey));
        }
    }

    @Nested
    class Error {

        @Test
        void shouldReturn400IfMissingParams() throws Json.JsonException {
            // Given
            Map<String, String> headers = new HashMap<>();

            var requestBodyWithNullCredential =
                    buildPasskeysCreateRequestBody(
                            null,
                            PRIMARY_PASSKEY_ID,
                            TEST_AAGUID,
                            false,
                            0,
                            PASSKEY_TRANSPORTS,
                            false,
                            false,
                            false);

            // When
            var response =
                    makeRequest(
                            Optional.of(requestBodyWithNullCredential),
                            headers,
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", PUBLIC_SUBJECT_ID));

            // Then
            assertThat(response.getStatusCode(), equalTo(400));
            assertThat(response, hasJsonBody(ErrorResponse.REQUEST_MISSING_PARAMS));
        }

        @Test
        void shouldReturn409IfPasskeyExists() throws Json.JsonException {
            // Given
            Map<String, String> headers = new HashMap<>();

            dynamoPasskeyService.savePasskeyIfUnique(
                    buildGenericPasskeyForUserWithSubjectId(PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID));

            var requestBodyWithDuplicatePasskeyId =
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
            var response =
                    makeRequest(
                            Optional.of(requestBodyWithDuplicatePasskeyId),
                            headers,
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", PUBLIC_SUBJECT_ID));

            // Then
            assertThat(response.getStatusCode(), equalTo(409));
            assertThat(response, hasJsonBody(ErrorResponse.PASSKEY_ALREADY_EXISTS));
        }

        @Test
        void shouldReturn422IfInvalidAaguid() throws Json.JsonException {
            // Given
            Map<String, String> headers = new HashMap<>();

            var requestBodyWithInvalidAaguid =
                    buildPasskeysCreateRequestBody(
                            CREDENTIAL,
                            PRIMARY_PASSKEY_ID,
                            "some-invalid-aaguid",
                            false,
                            0,
                            PASSKEY_TRANSPORTS,
                            false,
                            false,
                            false);

            // When
            var response =
                    makeRequest(
                            Optional.of(requestBodyWithInvalidAaguid),
                            headers,
                            Collections.emptyMap(),
                            Map.of("publicSubjectId", PUBLIC_SUBJECT_ID));

            // Then
            assertThat(response.getStatusCode(), equalTo(422));
            assertThat(response, hasJsonBody(ErrorResponse.INVALID_AAGUID));
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
}
