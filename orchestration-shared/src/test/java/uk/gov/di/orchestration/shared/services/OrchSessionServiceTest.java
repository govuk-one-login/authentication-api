package uk.gov.di.orchestration.shared.services;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.exceptions.OrchSessionException;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OrchSessionServiceTest {
    private static final String SESSION_ID = "test-session-id";
    private static final long VALID_TTL = Instant.now().plusSeconds(100).getEpochSecond();
    private static final long EXPIRED_TTL = Instant.now().minusSeconds(100).getEpochSecond();
    private static final Key SESSION_ID_PARTITION_KEY =
            Key.builder().partitionValue(SESSION_ID).build();

    private final DynamoDbTable<OrchSessionItem> table = mock(DynamoDbTable.class);
    private final DynamoDbClient dynamoDbClient = mock(DynamoDbClient.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private OrchSessionService orchSessionService;

    @BeforeEach
    void setup() {
        when(configurationService.getSessionExpiry()).thenReturn(86400L);
        orchSessionService = new OrchSessionService(dynamoDbClient, table, configurationService);
    }

    @Test
    void getSessionReturnsSessionWithValidTtl() {
        withValidSession();
        var session = orchSessionService.getSession(SESSION_ID);
        assertThat(session.isPresent(), equalTo(true));
    }

    @Test
    void getSessionReturnsEmptyOptionalWhenExpired() {
        withExpiredSession();
        var session = orchSessionService.getSession(SESSION_ID);
        assertThat(session.isPresent(), equalTo(false));
    }

    @Test
    void updateSessionThrowsOrchSessionExceptionWhenUpdateFails() {
        withFailedUpdate();
        var sessionToBeUpdated = new OrchSessionItem(SESSION_ID);
        assertThrows(
                OrchSessionException.class,
                () -> orchSessionService.updateSession(sessionToBeUpdated));
    }

    @Test
    void shouldReturnSessionFromSessionCookie() {
        withValidSession();

        Optional<OrchSessionItem> sessionFromSessionCookie =
                orchSessionService.getSessionFromSessionCookie(
                        Map.ofEntries(
                                Map.entry(
                                        CookieHelper.REQUEST_COOKIE_HEADER,
                                        String.format("gs=%s.456;", SESSION_ID))));

        assertTrue(sessionFromSessionCookie.isPresent());
        Assertions.assertEquals(SESSION_ID, sessionFromSessionCookie.get().getSessionId());
    }

    @Test
    void shouldReturnEmptyFromSessionCookieWhenHeaderIsIncorrect() {
        withValidSession();

        Optional<OrchSessionItem> session =
                orchSessionService.getSessionFromSessionCookie(
                        Map.ofEntries(
                                Map.entry(CookieHelper.REQUEST_COOKIE_HEADER, "gs=bad-value")));

        assertFalse(session.isPresent());
    }

    @Test
    void shouldReturnEmptyFromSessionCookieWhenSessionDoesNotExist() {
        Optional<OrchSessionItem> session =
                orchSessionService.getSessionFromSessionCookie(
                        Map.ofEntries(
                                Map.entry(
                                        CookieHelper.REQUEST_COOKIE_HEADER,
                                        String.format("gs=%s.456;", SESSION_ID))));

        assertFalse(session.isPresent());
    }

    private OrchSessionItem withValidSession() {
        OrchSessionItem existingSession = new OrchSessionItem(SESSION_ID).withTimeToLive(VALID_TTL);
        when(table.getItem(SESSION_ID_PARTITION_KEY)).thenReturn(existingSession);
        return existingSession;
    }

    private void withExpiredSession() {
        when(table.getItem(SESSION_ID_PARTITION_KEY))
                .thenReturn(new OrchSessionItem(SESSION_ID).withTimeToLive(EXPIRED_TTL));
    }

    private void withFailedUpdate() {
        doThrow(DynamoDbException.builder().message("Failed to update table").build())
                .when(table)
                .updateItem(any(OrchSessionItem.class));
    }
}