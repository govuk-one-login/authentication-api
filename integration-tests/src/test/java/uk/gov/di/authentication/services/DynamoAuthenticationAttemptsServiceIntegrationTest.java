package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAuthenticationAttemptsService;
import uk.gov.di.authentication.sharedtest.extensions.AuthenticationAttemptsStoreExtension;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DynamoAuthenticationAttemptsServiceIntegrationTest {

    private static final String ATTEMPT_IDENTIFIER = "attempt-identifier-1234";
    private static final String NON_EXISTENT_ATTEMPT_IDENTIFIER =
            "non-existent-attempt-identifier-1234";

    @RegisterExtension
    protected static final AuthenticationAttemptsStoreExtension authCodeExtension =
            new AuthenticationAttemptsStoreExtension();

    DynamoAuthenticationAttemptsService dynamoAuthenticationAttemptsService =
            new DynamoAuthenticationAttemptsService(ConfigurationService.getInstance());

    private void setUpDynamo() {
        authCodeExtension.addCode(ATTEMPT_IDENTIFIER);
    }

    @Test
    void shouldAddCode() {
        setUpDynamo();

        var authenticationAttempts =
                dynamoAuthenticationAttemptsService.getAuthenticationAttempts(ATTEMPT_IDENTIFIER);
        assertTrue(authenticationAttempts.isPresent());
    }

    @Test
    void shouldGetIncorrectReauthEmailCountForUser() {
        var ttl = Instant.now().getEpochSecond() + 60L;

        // Setup the count
        dynamoAuthenticationAttemptsService.createOrIncrementCount(ATTEMPT_IDENTIFIER, ttl);

        // Retrieve the count
        var incorrectEmailCount =
                dynamoAuthenticationAttemptsService
                        .getAuthenticationAttempts(ATTEMPT_IDENTIFIER)
                        .get()
                        .getCount();

        assertEquals(1, incorrectEmailCount);
    }

    @Test
    void shouldNotRetrieveANonExistentCount() {
        var count =
                dynamoAuthenticationAttemptsService.getAuthenticationAttempts(
                        NON_EXISTENT_ATTEMPT_IDENTIFIER);

        assertTrue(count.isEmpty());
    }

    @Test
    void shouldNotRetrieveACountWithAnExpiredTTL() {
        var expiredTTL = Instant.now().getEpochSecond() - 1L;

        // Setup the count
        dynamoAuthenticationAttemptsService.createOrIncrementCount(ATTEMPT_IDENTIFIER, expiredTTL);

        var count =
                dynamoAuthenticationAttemptsService.getAuthenticationAttempts(ATTEMPT_IDENTIFIER);

        assertTrue(count.isEmpty());
    }

    @Test
    void shouldIncrementExistingCountWhenAuthenticationAttemptFails() {
        var nonExpiredTTL = Instant.now().getEpochSecond() + 1000000L;

        dynamoAuthenticationAttemptsService.createOrIncrementCount(ATTEMPT_IDENTIFIER, nonExpiredTTL);
        dynamoAuthenticationAttemptsService.createOrIncrementCount(ATTEMPT_IDENTIFIER, nonExpiredTTL);

        var count = dynamoAuthenticationAttemptsService.getAuthenticationAttempts(ATTEMPT_IDENTIFIER);
        assertEquals(2, count.get().getCount());
    }
}
