package uk.gov.di.accountdata.lambda;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
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

    @BeforeEach
    void setUp() {
        handler = new PasskeysUpdateHandler(TEST_CONFIGURATION_SERVICE);
    }

    @Test
    void shouldUpdateAPasskey() {
        // Given
        var existingPasskey =
                buildGenericPasskeyForUserWithSubjectId(PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID)
                        .withPasskeySignCount(1)
                        .withLastUsed(Instant.now().minusSeconds(30).toString());
        dynamoPasskeyService.savePasskeyIfUnique(existingPasskey);
        Map<String, String> headers = new HashMap<>();
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
                        headers,
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
}
