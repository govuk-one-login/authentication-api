package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAmcStateService;
import uk.gov.di.authentication.sharedtest.extensions.AMCStateExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DynamoAMCStateServiceIntegrationTest {
    private static final ConfigurationService configurationService =
            ConfigurationService.getInstance();

    @RegisterExtension
    protected static final AMCStateExtension amcStateServiceExtension = new AMCStateExtension();

    private final DynamoAmcStateService dynamoAmcStateService =
            new DynamoAmcStateService(configurationService);

    @Test
    void shouldStoreValuesCorrectly() {
        var authenticationState = "abcdef";
        var clientSessionId = "some-client-session-id";
        dynamoAmcStateService.store(authenticationState, clientSessionId);

        var result = dynamoAmcStateService.get(authenticationState);
        assertTrue(result.isPresent());
        assertEquals(clientSessionId, result.get().getClientSessionId());
    }
}
