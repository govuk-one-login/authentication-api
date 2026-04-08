package uk.gov.di.accountdata.lambda;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.accountdata.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.accountdata.extensions.AuthenticatorExtension;
import uk.gov.di.authentication.accountdata.entity.passkey.Passkey;
import uk.gov.di.authentication.accountdata.lambda.PasskeysUpdateHandler;
import uk.gov.di.authentication.accountdata.services.DynamoPasskeyService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.LAST_USED_AT;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PRIMARY_PASSKEY_ID;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PUBLIC_SUBJECT_ID;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.SIGN_COUNT;
import static uk.gov.di.authentication.accountdata.helpers.PasskeysTestHelper.buildGenericPasskeyForUserWithSubjectId;

class PasskeysUpdateHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    DynamoPasskeyService dynamoPasskeyService =
            new DynamoPasskeyService(ConfigurationService.getInstance());

    @RegisterExtension
    protected static final AuthenticatorExtension authenticatorExtension =
            new AuthenticatorExtension();

    private static final Passkey EXISTING_PASSKEY =
            buildGenericPasskeyForUserWithSubjectId(PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID)
                    .withPasskeySignCount(SIGN_COUNT)
                    .withLastUsed(LAST_USED_AT);
    private static final int UPDATED_SIGN_COUNT = SIGN_COUNT + 1;
    private static final String UPDATED_LAST_USED_AT =
            Instant.parse(LAST_USED_AT).plus(1, ChronoUnit.MINUTES).toString();

    @BeforeEach
    void setUp() {
        handler = new PasskeysUpdateHandler(ConfigurationService.getInstance());
        dynamoPasskeyService.savePasskeyIfUnique(EXISTING_PASSKEY);
    }

    @Nested
    class Success {

        @Test
        void shouldUpdateAPasskey() {
            // Given
            var requestBody =
                    """
                            {
                                "signCount": %d,
                                "lastUsedAt": "%s"
                            }"""
                            .formatted(UPDATED_SIGN_COUNT, UPDATED_LAST_USED_AT);

            // When
            var response =
                    makeRequest(
                            Optional.of(requestBody),
                            new HashMap<String, String>(),
                            Collections.emptyMap(),
                            Map.of(
                                    "publicSubjectId",
                                    PUBLIC_SUBJECT_ID,
                                    "passkeyId",
                                    PRIMARY_PASSKEY_ID));

            // Then
            assertEquals(204, response.getStatusCode());
            assertEquals("", response.getBody());

            var savedPasskeysForUser = dynamoPasskeyService.getPasskeysForUser(PUBLIC_SUBJECT_ID);
            var savedPasskey = savedPasskeysForUser.get(0);

            assertEquals(PRIMARY_PASSKEY_ID, savedPasskey.getCredentialId());
            assertEquals(UPDATED_SIGN_COUNT, savedPasskey.getPasskeySignCount());
            assertEquals(UPDATED_LAST_USED_AT, savedPasskey.getLastUsed());
        }
    }

    @Nested
    class Error {

        @Test
        void shouldReturn404ForPasskeyNotFound() {
            // Given
            var requestPasskeyId = "a different passkey";

            var requestBody =
                    """
                            {
                                "signCount": %d,
                                "lastUsedAt": "%s"
                            }"""
                            .formatted(UPDATED_SIGN_COUNT, UPDATED_LAST_USED_AT);

            // When
            var response =
                    makeRequest(
                            Optional.of(requestBody),
                            new HashMap<String, String>(),
                            Collections.emptyMap(),
                            Map.of(
                                    "publicSubjectId",
                                    PUBLIC_SUBJECT_ID,
                                    "passkeyId",
                                    requestPasskeyId));

            // Then
            assertEquals(404, response.getStatusCode());

            assertSavedPasskeyUnchanged(PUBLIC_SUBJECT_ID, EXISTING_PASSKEY);
        }

        @Test
        void shouldReturn400IfInvalidRequestBody() {
            // Given
            var requestBody = "{\"foo\": \"bar\"}";

            // When
            var response =
                    makeRequest(
                            Optional.of(requestBody),
                            new HashMap<String, String>(),
                            Collections.emptyMap(),
                            Map.of(
                                    "publicSubjectId",
                                    PUBLIC_SUBJECT_ID,
                                    "passkeyId",
                                    PRIMARY_PASSKEY_ID));

            // Then
            assertEquals(400, response.getStatusCode());

            assertSavedPasskeyUnchanged(PUBLIC_SUBJECT_ID, EXISTING_PASSKEY);
        }

        @Test
        void shouldReturn400IfInvalidTimestamp() {
            // Given
            var invalidLastUsedAt = "not a timestamp";

            var requestBody =
                    """
                            {
                                "signCount": %d,
                                "lastUsedAt": "%s"
                            }"""
                            .formatted(UPDATED_SIGN_COUNT, invalidLastUsedAt);

            // When
            var response =
                    makeRequest(
                            Optional.of(requestBody),
                            new HashMap<String, String>(),
                            Collections.emptyMap(),
                            Map.of(
                                    "publicSubjectId",
                                    PUBLIC_SUBJECT_ID,
                                    "passkeyId",
                                    PRIMARY_PASSKEY_ID));

            // Then
            assertEquals(400, response.getStatusCode());

            assertSavedPasskeyUnchanged(PUBLIC_SUBJECT_ID, EXISTING_PASSKEY);
        }
    }

    private void assertSavedPasskeyUnchanged(String publicSubjectId, Passkey existingPasskey) {
        var savedPasskeysForUser = dynamoPasskeyService.getPasskeysForUser(publicSubjectId);
        assertEquals(1, savedPasskeysForUser.size());
        var savedPasskey = savedPasskeysForUser.get(0);

        // assert passkey not updated
        assertEquals(existingPasskey.getCredentialId(), savedPasskey.getCredentialId());
        assertEquals(existingPasskey.getPasskeySignCount(), savedPasskey.getPasskeySignCount());
        assertEquals(existingPasskey.getLastUsed(), savedPasskey.getLastUsed());
    }
}
