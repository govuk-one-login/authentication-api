package uk.gov.di.orchestration.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.model.GetItemEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.exceptions.OrchClientSessionException;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OrchClientSessionServiceTest {
    private static final String CLIENT_SESSION_ID = "test-client-session-id";
    private static final String CLIENT_NAME = "test-client-name";
    private static final long VALID_TTL = Instant.now().plusSeconds(100).getEpochSecond();
    private static final long EXPIRED_TTL = Instant.now().minusSeconds(100).getEpochSecond();
    private static final Key CLIENT_SESSION_ID_PARTITION_KEY =
            Key.builder().partitionValue(CLIENT_SESSION_ID).build();
    private static final GetItemEnhancedRequest CLIENT_SESSION_GET_REQUEST =
            GetItemEnhancedRequest.builder()
                    .key(CLIENT_SESSION_ID_PARTITION_KEY)
                    .consistentRead(false)
                    .build();
    private final DynamoDbTable<OrchClientSessionItem> table = mock(DynamoDbTable.class);
    private final DynamoDbClient dynamoDbClient = mock(DynamoDbClient.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private OrchClientSessionService clientSessionService;

    @BeforeEach
    void setup() {
        when(configurationService.getSessionExpiry()).thenReturn(86400L);
        clientSessionService =
                new OrchClientSessionService(dynamoDbClient, table, configurationService);
    }

    @Test
    void shouldStoreClientSession() {
        var clientSession = withValidClientSession();
        clientSessionService.storeClientSession(clientSession);
        verify(table).putItem(clientSession);
    }

    @Test
    void shouldThrowWhenFailingToStoreClientSession() {
        withFailedPut();
        var clientSession = new OrchClientSessionItem(CLIENT_SESSION_ID);
        assertThrows(
                OrchClientSessionException.class,
                () -> clientSessionService.storeClientSession(clientSession));
    }

    @Test
    void shouldGetClientSessionById() {
        withValidClientSession();
        var clientSession = clientSessionService.getClientSession(CLIENT_SESSION_ID);
        assertTrue(clientSession.isPresent());
        assertEquals(CLIENT_SESSION_ID, clientSession.get().getClientSessionId());
    }

    @Test
    void shouldThrowWhenFailingToGetClientSessionById() {
        withFailedGet();
        assertThrows(
                OrchClientSessionException.class,
                () -> clientSessionService.getClientSession(CLIENT_SESSION_ID));
    }

    @Test
    void shouldNotGetClientSessionByIdWhenNoClientSessionExists() {
        var clientSession = clientSessionService.getClientSession("not-a-client-session");
        assertTrue(clientSession.isEmpty());
    }

    @Test
    void shouldNotGetClientSessionByIdWhenClientSessionExistsButTimeToLiveExpired() {
        withExpiredClientSession();
        var clientSession = clientSessionService.getClientSession(CLIENT_SESSION_ID);
        assertTrue(clientSession.isEmpty());
    }

    @Test
    void shouldUpdateClientSession() {
        var existingSession = withValidClientSession();
        var sessionToBeUpdated = existingSession.withClientName("new-client-name");
        clientSessionService.updateStoredClientSession(sessionToBeUpdated);
        verify(table).updateItem(sessionToBeUpdated);
    }

    @Test
    void shouldThrowWhenUpdatingClientSessionFails() {
        withFailedUpdate();
        var sessionToBeUpdated = new OrchClientSessionItem(CLIENT_SESSION_ID);
        assertThrows(
                OrchClientSessionException.class,
                () -> clientSessionService.updateStoredClientSession(sessionToBeUpdated));
    }

    @Test
    void shouldDeleteClientSession() {
        var existingClientSession = withValidClientSession();
        clientSessionService.deleteStoredClientSession(CLIENT_SESSION_ID);
        verify(table).getItem(CLIENT_SESSION_GET_REQUEST);
        verify(table).deleteItem(existingClientSession);
    }

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
        when(table.getItem(
                        GetItemEnhancedRequest.builder()
                                .consistentRead(false)
                                .key(CLIENT_SESSION_ID_PARTITION_KEY)
                                .build()))
                .thenReturn(existingSession);
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

    private void withFailedPut() {
        doThrow(DynamoDbException.builder().message("Failed to put item in table").build())
                .when(table)
                .putItem(any(OrchClientSessionItem.class));
    }

    private void withFailedGet() {
        doThrow(DynamoDbException.builder().message("Failed to get from table").build())
                .when(table)
                .getItem(any(GetItemEnhancedRequest.class));
    }

    private void withFailedUpdate() {
        doThrow(DynamoDbException.builder().message("Failed to update table").build())
                .when(table)
                .updateItem(any(OrchClientSessionItem.class));
    }

    private void withFailedDelete() {
        doThrow(DynamoDbException.builder().message("Failed to delete from table").build())
                .when(table)
                .deleteItem(any(OrchClientSessionItem.class));
    }
}
