package uk.gov.di.accountdata.lambda;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.accountdata.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.accountdata.extensions.AuthenticatorExtension;
import uk.gov.di.authentication.accountdata.entity.passkey.Passkey;
import uk.gov.di.authentication.accountdata.lambda.PasskeysDeleteHandler;
import uk.gov.di.authentication.accountdata.services.DynamoPasskeyService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PRIMARY_PASSKEY_ID;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PUBLIC_SUBJECT_ID;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.SECONDARY_PASSKEY_ID;
import static uk.gov.di.authentication.accountdata.helpers.PasskeysTestHelper.buildGenericPasskeyForUserWithSubjectId;

class PasskeysDeleteHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private final ConfigurationService configurationService = ConfigurationService.getInstance();
    DynamoPasskeyService dynamoPasskeyService = new DynamoPasskeyService(configurationService);
    private static final Map<String, Object> AUTHORIZER_PARAMS =
            Map.of("principalId", PUBLIC_SUBJECT_ID);

    @RegisterExtension
    protected static final AuthenticatorExtension authenticatorExtension =
            new AuthenticatorExtension();

    @BeforeEach
    void setUp() {
        handler = new PasskeysDeleteHandler(configurationService);
    }

    @Nested
    class Success {

        @Test
        void shouldDeleteAPasskey() {
            // Given
            Passkey passkeyToDelete =
                    buildGenericPasskeyForUserWithSubjectId(PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID);
            Passkey otherPasskey =
                    buildGenericPasskeyForUserWithSubjectId(
                            PUBLIC_SUBJECT_ID, SECONDARY_PASSKEY_ID);
            dynamoPasskeyService.savePasskeyIfUnique(passkeyToDelete);
            dynamoPasskeyService.savePasskeyIfUnique(otherPasskey);

            // Check that we definitely have both passkeys saved before we proceed with the request
            // to delete
            var passkeysBeforeDelete = dynamoPasskeyService.getPasskeysForUser(PUBLIC_SUBJECT_ID);
            assertEquals(2, passkeysBeforeDelete.size());

            // When
            var pathParams =
                    Map.ofEntries(
                            Map.entry("publicSubjectId", PUBLIC_SUBJECT_ID),
                            Map.entry("passkeyId", PRIMARY_PASSKEY_ID));
            var response =
                    makeRequest(
                            Optional.empty(),
                            new HashMap<>(),
                            Collections.emptyMap(),
                            pathParams,
                            AUTHORIZER_PARAMS);

            // Then
            assertThat(response.getStatusCode(), equalTo(204));
            assertThat(response.getBody(), equalTo(""));

            var passkeysAfterDelete = dynamoPasskeyService.getPasskeysForUser(PUBLIC_SUBJECT_ID);
            assertEquals(1, passkeysAfterDelete.size());
            var savedPasskey = passkeysAfterDelete.get(0);

            assertThat(savedPasskey.getCredentialId(), equalTo(otherPasskey.getCredentialId()));
        }
    }

    @Nested
    class Failure {
        @Test
        void shouldReturn404WhenPasskeyNotFound() {
            // Given
            Passkey existingPasskey =
                    buildGenericPasskeyForUserWithSubjectId(PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID);
            dynamoPasskeyService.savePasskeyIfUnique(existingPasskey);

            // Check that we definitely have both a passkey saved before we proceed with the request
            // to delete
            var passkeysBeforeDelete = dynamoPasskeyService.getPasskeysForUser(PUBLIC_SUBJECT_ID);
            assertEquals(1, passkeysBeforeDelete.size());

            // When
            var pathParams =
                    Map.ofEntries(
                            Map.entry("publicSubjectId", PUBLIC_SUBJECT_ID),
                            Map.entry("passkeyId", SECONDARY_PASSKEY_ID));
            var response =
                    makeRequest(
                            Optional.empty(),
                            new HashMap<>(),
                            Collections.emptyMap(),
                            pathParams,
                            AUTHORIZER_PARAMS);

            // Then
            assertThat(response.getStatusCode(), equalTo(404));

            var passkeysAfterDelete = dynamoPasskeyService.getPasskeysForUser(PUBLIC_SUBJECT_ID);
            assertEquals(passkeysBeforeDelete.size(), passkeysAfterDelete.size());

            var passkeyAfterDelete = passkeysAfterDelete.get(0);
            assertThat(
                    passkeyAfterDelete.getCredentialId(),
                    equalTo(existingPasskey.getCredentialId()));
        }
    }
}
