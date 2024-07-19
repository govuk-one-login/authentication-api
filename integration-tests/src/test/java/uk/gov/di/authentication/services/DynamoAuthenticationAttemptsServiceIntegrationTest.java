package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAuthenticationAttemptsService;
import uk.gov.di.authentication.sharedtest.extensions.AuthenticationAttemptsStoreExtension;

import static org.junit.jupiter.api.Assertions.assertTrue;

class DynamoAuthenticationAttemptsServiceIntegrationTest {

    private static final String ATTEMPT_IDENTIFIER = "attempt-identifier-1234";

    @RegisterExtension
    protected static final AuthenticationAttemptsStoreExtension authCodeExtension =
            new AuthenticationAttemptsStoreExtension();

    DynamoAuthenticationAttemptsService dynamoAuthenticationAttemptsService =
            new DynamoAuthenticationAttemptsService(ConfigurationService.getInstance());

    private void setUpDynamo() {
        authCodeExtension.addCode(ATTEMPT_IDENTIFIER);
    }

    @Test
    void shoudAddCode() {
        setUpDynamo();

        var authenticationAttempts =
                dynamoAuthenticationAttemptsService.getAuthenticationAttempts(ATTEMPT_IDENTIFIER);
        assertTrue(authenticationAttempts.isPresent());
    }
}
