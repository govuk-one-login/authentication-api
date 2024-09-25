package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthSessionServiceTest {
    private final DynamoDbTable<AuthSessionItem> mockTable = mock(DynamoDbTable.class);
    private final DynamoDbClient mockClient = mock(DynamoDbClient.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final String sessionId = "test-session-id";
    private final Key sessionIdPartitionKey = Key.builder().partitionValue(sessionId).build();
    private AuthSessionService authSessionService;

    @BeforeEach
    void testSetup() {
        authSessionService = new AuthSessionService(mockClient, mockTable, configurationService);
    }

    @Test
    void getSessionReturnsSessionWithValidTtl() {
        withValidSession();
        var session = authSessionService.getSession(sessionId);
        assertThat(session.isPresent(), equalTo(true));
    }

    @Test
    void getSessionReturnsEmptyOptionalWhenExpired() {
        withExpiredSession();
        var session = authSessionService.getSession(sessionId);
        assertThat(session.isPresent(), equalTo(false));
    }

    @Test
    void updateSessionThrowsAnyDynamoExceptions() {
        withFailedUpdate();
        var sessionToBeUpdated =
                new AuthSessionItem()
                        .withSessionId(sessionId)
                        .withAccountState(AuthSessionItem.AccountState.EXISTING);
        assertThrows(
                DynamoDbException.class,
                () -> authSessionService.updateSession(sessionToBeUpdated));
    }

    private void withValidSession() {
        when(mockTable.getItem(sessionIdPartitionKey))
                .thenReturn(
                        new AuthSessionItem()
                                .withSessionId(sessionId)
                                .withTimeToLive(NowHelper.now().getTime()));
    }

    private void withExpiredSession() {
        long septemberThe7th2002 = 1031405521;
        when(mockTable.getItem(sessionIdPartitionKey))
                .thenReturn(
                        new AuthSessionItem()
                                .withSessionId(sessionId)
                                .withTimeToLive(septemberThe7th2002));
    }

    private void withFailedUpdate() {
        doThrow(DynamoDbException.builder().message("Failed to update table").build())
                .when(mockTable)
                .updateItem(any(AuthSessionItem.class));
    }
}
