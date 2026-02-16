package uk.gov.di.orchestration.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.enhanced.dynamodb.model.GetItemEnhancedRequest;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.exceptions.OrchClientSessionException;
import uk.gov.di.orchestration.sharedtest.basetest.BaseDynamoServiceTest;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

// QualityGateUnitTest
class OrchClientSessionServiceTest extends BaseDynamoServiceTest<OrchClientSessionItem> {
    private static final String CLIENT_SESSION_ID = "test-client-session-id";
    private static final String CLIENT_NAME = "test-client-name";
    private static final long VALID_TTL = Instant.now().plusSeconds(100).getEpochSecond();
    private static final long EXPIRED_TTL = Instant.now().minusSeconds(100).getEpochSecond();
    private static final GetItemEnhancedRequest CLIENT_SESSION_GET_REQUEST =
            getRequestFor(CLIENT_SESSION_ID);
    private OrchClientSessionService clientSessionService;

    @BeforeEach
    void setup() {
        when(configurationService.getSessionExpiry()).thenReturn(86400L);
        clientSessionService =
                new OrchClientSessionService(dynamoDbClient, table, configurationService);
    }

    // QualityGateRegressionTest
    @Test
    void shouldStoreClientSession() {
        var clientSession = withValidClientSession();
        clientSessionService.storeClientSession(clientSession);
        verify(table).putItem(clientSession);
    }

    // QualityGateRegressionTest
    @Test
    void shouldThrowWhenFailingToStoreClientSession() {
        withFailedPut();
        var clientSession = new OrchClientSessionItem(CLIENT_SESSION_ID);
        assertThrows(
                OrchClientSessionException.class,
                () -> clientSessionService.storeClientSession(clientSession));
    }

    // QualityGateRegressionTest
    @Test
    void shouldGetClientSessionById() {
        withValidClientSession();
        var clientSession = clientSessionService.getClientSession(CLIENT_SESSION_ID);
        assertTrue(clientSession.isPresent());
        assertEquals(CLIENT_SESSION_ID, clientSession.get().getClientSessionId());
    }

    // QualityGateRegressionTest
    @Test
    void shouldThrowWhenFailingToGetClientSessionById() {
        withFailedGet();
        assertThrows(
                OrchClientSessionException.class,
                () -> clientSessionService.getClientSession(CLIENT_SESSION_ID));
    }

    // QualityGateRegressionTest
    @Test
    void shouldNotGetClientSessionByIdWhenNoClientSessionExists() {
        var clientSession = clientSessionService.getClientSession("not-a-client-session");
        assertTrue(clientSession.isEmpty());
    }

    // QualityGateRegressionTest
    @Test
    void shouldNotGetClientSessionByIdWhenClientSessionExistsButTimeToLiveExpired() {
        withExpiredClientSession();
        var clientSession = clientSessionService.getClientSession(CLIENT_SESSION_ID);
        assertTrue(clientSession.isEmpty());
    }

    // QualityGateRegressionTest
    @Test
    void shouldUpdateClientSession() {
        var existingSession = withValidClientSession();
        var sessionToBeUpdated = existingSession.withClientName("new-client-name");
        clientSessionService.updateStoredClientSession(sessionToBeUpdated);
        verify(table).updateItem(sessionToBeUpdated);
    }

    // QualityGateRegressionTest
    @Test
    void shouldThrowWhenUpdatingClientSessionFails() {
        withFailedUpdate();
        var sessionToBeUpdated = new OrchClientSessionItem(CLIENT_SESSION_ID);
        assertThrows(
                OrchClientSessionException.class,
                () -> clientSessionService.updateStoredClientSession(sessionToBeUpdated));
    }

    // QualityGateRegressionTest
    @Test
    void shouldDeleteClientSession() {
        var existingClientSession = withValidClientSession();
        clientSessionService.deleteStoredClientSession(CLIENT_SESSION_ID);
        verify(table).getItem(CLIENT_SESSION_GET_REQUEST);
        verify(table).deleteItem(existingClientSession);
    }

    // QualityGateRegressionTest
    @Test
    void shouldThrowWhenDeletingClientSessionFails() {
        withValidClientSession();
        withFailedDelete();
        assertThrows(
                OrchClientSessionException.class,
                () -> clientSessionService.deleteStoredClientSession(CLIENT_SESSION_ID));
    }

    private OrchClientSessionItem withValidClientSession() {
        OrchClientSessionItem existingSession =
                new OrchClientSessionItem(CLIENT_SESSION_ID)
                        .withClientName(CLIENT_NAME)
                        .withTimeToLive(VALID_TTL);
        when(table.getItem(CLIENT_SESSION_GET_REQUEST)).thenReturn(existingSession);
        return existingSession;
    }

    private void withExpiredClientSession() {
        OrchClientSessionItem existingSession =
                new OrchClientSessionItem(CLIENT_SESSION_ID)
                        .withClientName(CLIENT_NAME)
                        .withTimeToLive(EXPIRED_TTL);
        when(table.getItem(CLIENT_SESSION_GET_REQUEST)).thenReturn(existingSession);
    }
}
