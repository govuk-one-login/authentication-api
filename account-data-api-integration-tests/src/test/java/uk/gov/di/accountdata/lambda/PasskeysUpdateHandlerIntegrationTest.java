package uk.gov.di.accountdata.lambda;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.accountdata.entity.passkey.Passkey;
import uk.gov.di.authentication.accountdata.lambda.PasskeysUpdateHandler;
import uk.gov.di.authentication.accountdata.services.DynamoPasskeyService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AuthenticatorExtension;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PRIMARY_PASSKEY_ID;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PUBLIC_SUBJECT_ID;
import static uk.gov.di.authentication.accountdata.helpers.PasskeysTestHelper.buildGenericPasskeyForUserWithSubjectId;

class PasskeysUpdateHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    DynamoPasskeyService dynamoPasskeyService =
            new DynamoPasskeyService(TEST_CONFIGURATION_SERVICE);

    @RegisterExtension
    protected static final AuthenticatorExtension authenticatorExtension =
            new AuthenticatorExtension();

    private static final Passkey EXISTING_PASSKEY =
            buildGenericPasskeyForUserWithSubjectId(PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID)
                    .withPasskeySignCount(1)
                    .withLastUsed(Instant.now().minusSeconds(30).toString());

    @BeforeEach
    void setUp() {
        handler = new PasskeysUpdateHandler(TEST_CONFIGURATION_SERVICE);
        dynamoPasskeyService.savePasskeyIfUnique(EXISTING_PASSKEY);
    }

    @Test
    void shouldUpdateAPasskey() {
        // Given
        var lastUsedAt = Instant.now().toString();
        var updatedSignCount = 4;

        var requestBody =
                """
                    {
                        "signCount": %d,
                        "lastUsedAt": "%s"
                    }"""
                        .formatted(updatedSignCount, lastUsedAt);

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
        assertEquals(updatedSignCount, savedPasskey.getPasskeySignCount());
        assertEquals(lastUsedAt, savedPasskey.getLastUsed());
    }

    @Test
    void shouldReturn404ForPasskeyNotFound() {
        // Given
        var lastUsedAt = Instant.now().toString();
        var updatedSignCount = 4;
        var requestPasskeyId = "a different passkey";

        var requestBody =
                """
                    {
                        "signCount": %d,
                        "lastUsedAt": "%s"
                    }"""
                        .formatted(updatedSignCount, lastUsedAt);

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
        var lastUsedAt = "not a timestamp";
        var updatedSignCount = 4;

        var requestBody =
                """
                    {
                        "signCount": %d,
                        "lastUsedAt": "%s"
                    }"""
                        .formatted(updatedSignCount, lastUsedAt);

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
