package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAmcStateService;
import uk.gov.di.authentication.sharedtest.extensions.AMCStateExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DynamoAMCStateServiceIntegrationTest {
    private static final ConfigurationService configurationService =
            ConfigurationService.getInstance();

    @RegisterExtension
    protected static final AMCStateExtension amcStateServiceExtension = new AMCStateExtension();

    private final DynamoAmcStateService dynamoAmcStateService =
            new DynamoAmcStateService(configurationService);

    private static final String AUTHENTICATION_STATE = "abcdef";
    private static final String CLIENT_SESSION_ID = "client-session-id";

    @Test
    void shouldStoreValuesCorrectly() {
        dynamoAmcStateService.store(AUTHENTICATION_STATE, CLIENT_SESSION_ID);

        var result = dynamoAmcStateService.get(AUTHENTICATION_STATE);

        assertTrue(result.isPresent());
        assertEquals(CLIENT_SESSION_ID, result.get().getClientSessionId());
    }

    @Test
    void shouldGetAStateCorrectly() {
        dynamoAmcStateService.store(AUTHENTICATION_STATE, CLIENT_SESSION_ID);

        var result = dynamoAmcStateService.getNonExpiredState(AUTHENTICATION_STATE);

        assertTrue(result.isPresent());
        assertEquals(CLIENT_SESSION_ID, result.get().getClientSessionId());
    }

    @Test
    void shouldNotGetAnExpiredState() {
        var now = Instant.now();
        var thirtyMinutesInTheFuture = now.plus(30L, ChronoUnit.MINUTES);
        var clockInTheFuture = Clock.fixed(thirtyMinutesInTheFuture, ZoneId.of("UTC"));
        // Here we set the clock in the service to be in the future rather than storing an amc state
        // with a ttl in the past to ensure
        // that this is testing the filtering in the code rather than the ttl cleanup of dynamo
        var service = new DynamoAmcStateService(configurationService, clockInTheFuture);
        amcStateServiceExtension.storeWithTTl(
                AUTHENTICATION_STATE, CLIENT_SESSION_ID, now.getEpochSecond());

        var result = service.getNonExpiredState(AUTHENTICATION_STATE);

        assertFalse(result.isPresent());
    }
}
