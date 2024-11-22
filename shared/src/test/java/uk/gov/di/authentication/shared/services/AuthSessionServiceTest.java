package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.exceptions.AuthSessionException;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;

class AuthSessionServiceTest {
    private static final String SESSION_ID = "test-session-id";
    private static final String NEW_SESSION_ID = "new-session-id";
    private static final long VALID_TTL = Instant.now().plusSeconds(100).getEpochSecond();
    private static final long EXPIRED_TTL = Instant.now().minusSeconds(100).getEpochSecond();
    private static final Key SESSION_ID_PARTITION_KEY =
            Key.builder().partitionValue(SESSION_ID).build();

    private final DynamoDbTable<AuthSessionItem> table = mock(DynamoDbTable.class);
    private final DynamoDbClient dynamoDbClient = mock(DynamoDbClient.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private AuthSessionService authSessionService;

    @BeforeEach
    void setup() {
        when(configurationService.getSessionExpiry()).thenReturn(86400L);
        authSessionService = new AuthSessionService(dynamoDbClient, table, configurationService);
    }

    @Test
    void getSessionReturnsSessionWithValidTtl() {
        withValidSession();
        var session = authSessionService.getSession(SESSION_ID);
        assertThat(session.isPresent(), equalTo(true));
    }

    @Test
    void getSessionReturnsEmptyOptionalWhenExpired() {
        withExpiredSession();
        var session = authSessionService.getSession(SESSION_ID);
        assertThat(session.isPresent(), equalTo(false));
    }

    @Test
    void updateSessionThrowsAnyDynamoExceptions() {
        withFailedUpdate();
        var sessionToBeUpdated =
                new AuthSessionItem()
                        .withSessionId(SESSION_ID)
                        .withAccountState(AuthSessionItem.AccountState.EXISTING);
        assertThrows(
                AuthSessionException.class,
                () -> authSessionService.updateSession(sessionToBeUpdated));
    }

    @Test
    void shouldAddNewSessionWhenNoPreviousSessionGiven() {
        authSessionService.addOrUpdateSessionId(Optional.empty(), NEW_SESSION_ID, null);

        ArgumentCaptor<AuthSessionItem> captor = ArgumentCaptor.forClass(AuthSessionItem.class);
        verify(table).putItem(captor.capture());
        AuthSessionItem savedItem = captor.getValue();

        assertThat(savedItem.getSessionId(), is(NEW_SESSION_ID));
        assertTrue(savedItem.getTimeToLive() > Instant.now().getEpochSecond());
    }

    @Test
    void shouldAddNewSessionWhenNoPreviousSessionExists() {
        withNoSession();

        authSessionService.addOrUpdateSessionId(Optional.of(SESSION_ID), NEW_SESSION_ID, null);

        ArgumentCaptor<AuthSessionItem> captor = ArgumentCaptor.forClass(AuthSessionItem.class);
        verify(table).putItem(captor.capture());
        AuthSessionItem savedItem = captor.getValue();

        assertThat(savedItem.getSessionId(), is(NEW_SESSION_ID));
        assertTrue(savedItem.getTimeToLive() > Instant.now().getEpochSecond());
    }

    @Test
    void shouldPutAndDeleteSessionWhenUpdatingSessionId() {
        AuthSessionItem existingSession = withValidSession();

        authSessionService.addOrUpdateSessionId(Optional.of(SESSION_ID), NEW_SESSION_ID, null);

        ArgumentCaptor<AuthSessionItem> captor = ArgumentCaptor.forClass(AuthSessionItem.class);
        verify(table).putItem(captor.capture());
        AuthSessionItem updatedItem = captor.getValue();

        assertThat(updatedItem.getSessionId(), is(NEW_SESSION_ID));
        assertTrue(updatedItem.getTimeToLive() > Instant.now().getEpochSecond());
        verify(table).deleteItem(existingSession);
    }

    @Test
    void shouldIncludeTheCurrentCredentialStrengthWhenUpdating() {
        withValidSession();

        authSessionService.addOrUpdateSessionId(
                Optional.of(SESSION_ID), NEW_SESSION_ID, CredentialTrustLevel.MEDIUM_LEVEL);

        ArgumentCaptor<AuthSessionItem> captor = ArgumentCaptor.forClass(AuthSessionItem.class);
        verify(table).putItem(captor.capture());
        AuthSessionItem savedItem = captor.getValue();

        assertThat(savedItem.getSessionId(), is(NEW_SESSION_ID));
        assertThat(savedItem.getCurrentCredentialStrength(), is(CredentialTrustLevel.MEDIUM_LEVEL));
    }

    @Test
    void shouldIncludeTheCurrentCredentialStrengthWhenNewSession() {
        withNoSession();

        authSessionService.addOrUpdateSessionId(
                Optional.empty(), NEW_SESSION_ID, CredentialTrustLevel.MEDIUM_LEVEL);

        ArgumentCaptor<AuthSessionItem> captor = ArgumentCaptor.forClass(AuthSessionItem.class);
        verify(table).putItem(captor.capture());
        AuthSessionItem savedItem = captor.getValue();

        assertThat(savedItem.getSessionId(), is(NEW_SESSION_ID));
        assertThat(savedItem.getCurrentCredentialStrength(), is(CredentialTrustLevel.MEDIUM_LEVEL));
    }

    @Test
    void shouldReturnEmptyWhenSessionIsExpired() {
        withExpiredSession();

        Optional<AuthSessionItem> result = authSessionService.getSession(SESSION_ID);

        assertTrue(result.isEmpty());
    }

    @Test
    void getSessionFromRequestHeadersReturnsEmptyWhenNoSessionId() {
        var session = authSessionService.getSessionFromRequestHeaders(Map.of());
        assertThat(session.isEmpty(), equalTo(true));
    }

    @Test
    void shouldGetSessionFromRequestHeaders() {
        var expectedSession = withValidSession();
        var headerMap = Map.of(SESSION_ID_HEADER, SESSION_ID);
        var session = authSessionService.getSessionFromRequestHeaders(headerMap);
        assertThat(session.isPresent(), equalTo(true));
        assertThat(session.get(), equalTo(expectedSession));
    }

    @Test
    void shouldReturnEmptyOptionalWhenNoSessionIdHeader() {
        withValidSession();
        var session = authSessionService.getSessionFromRequestHeaders(Map.of());
        assertThat(session.isEmpty(), equalTo(true));
    }

    @Test
    void shouldReturnEmptyWhenNoSessionExistsForHeader() {
        withNoSession();
        var session =
                authSessionService.getSessionFromRequestHeaders(
                        Map.of(SESSION_ID_HEADER, SESSION_ID));
        assertThat(session.isEmpty(), equalTo(true));
    }

    @Test
    void throwsAuthExceptionWhenGetFromRequestHeadersFails() {
        withFailedGet();
        var headerMap = Map.of(SESSION_ID_HEADER, SESSION_ID);
        assertThrows(
                AuthSessionException.class,
                () -> authSessionService.getSessionFromRequestHeaders(headerMap));
    }

    private AuthSessionItem withValidSession() {
        AuthSessionItem existingSession =
                new AuthSessionItem().withSessionId(SESSION_ID).withTimeToLive(VALID_TTL);
        when(table.getItem(SESSION_ID_PARTITION_KEY)).thenReturn(existingSession);
        return existingSession;
    }

    private void withExpiredSession() {
        when(table.getItem(SESSION_ID_PARTITION_KEY))
                .thenReturn(
                        new AuthSessionItem()
                                .withSessionId(SESSION_ID)
                                .withTimeToLive(EXPIRED_TTL));
    }

    private void withNoSession() {
        when(table.getItem(SESSION_ID_PARTITION_KEY)).thenReturn(null);
    }

    private void withFailedUpdate() {
        doThrow(DynamoDbException.builder().message("Failed to update table").build())
                .when(table)
                .updateItem(any(AuthSessionItem.class));
    }

    private void withFailedGet() {
        doThrow(DynamoDbException.builder().message("Failed to get item from table").build())
                .when(table)
                .getItem(SESSION_ID_PARTITION_KEY);
    }
}
