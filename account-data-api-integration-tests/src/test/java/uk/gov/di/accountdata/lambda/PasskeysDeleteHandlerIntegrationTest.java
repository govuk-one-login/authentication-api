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
            var response =
                    makeRequest(
                            Optional.empty(),
                            new HashMap<>(),
                            Collections.emptyMap(),
                            Map.of(
                                    "publicSubjectId",
                                    PUBLIC_SUBJECT_ID,
                                    "passkeyId",
                                    PRIMARY_PASSKEY_ID),
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
}
