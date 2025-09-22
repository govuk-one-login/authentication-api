package uk.gov.di.orchestration.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.model.GetItemEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.exceptions.OrchSessionException;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.sharedtest.basetest.BaseDynamoServiceTest;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OrchSessionServiceTest extends BaseDynamoServiceTest<OrchSessionItem> {
    private static final String SESSION_ID = "test-session-id";
    private static final long VALID_TTL = Instant.now().plusSeconds(100).getEpochSecond();
    private static final long EXPIRED_TTL = Instant.now().minusSeconds(100).getEpochSecond();
    private static final Key SESSION_ID_PARTITION_KEY =
            Key.builder().partitionValue(SESSION_ID).build();
    private static final GetItemEnhancedRequest SESSION_GET_REQUEST =
            GetItemEnhancedRequest.builder()
                    .key(SESSION_ID_PARTITION_KEY)
                    .consistentRead(true)
                    .build();
    private OrchSessionService orchSessionService;

    @BeforeEach
    void setup() {
        when(configurationService.getSessionExpiry()).thenReturn(86400L);
        orchSessionService = new OrchSessionService(dynamoDbClient, table, configurationService);
    }

    @Test
    void newSessionHasDefaultValues() {
        var session = new OrchSessionItem(SESSION_ID);
        assertThat(session.getProcessingIdentityAttempts(), equalTo(0));
        assertThat(session.getIsNewAccount(), equalTo(OrchSessionItem.AccountState.UNKNOWN));
        assertThat(session.getClientSessions(), equalTo(new ArrayList<>()));
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
    void deleteSessionThrowsOrchSessionExceptionWhenDeleteFails() {
        var orchSession = withValidSession();
        withFailedDelete(orchSession);

        var exception =
                assertThrows(
                        OrchSessionException.class,
                        () -> orchSessionService.deleteSession(SESSION_ID));
        assertEquals("Error deleting orch session item", exception.getMessage());
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
        assertEquals(SESSION_ID, sessionFromSessionCookie.get().getSessionId());
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

    @Test
    void shouldRetrieveSessionUsingRequestHeaders() {
        withValidSession();

        var session =
                orchSessionService.getSessionFromRequestHeaders(Map.of("Session-Id", SESSION_ID));

        assertTrue(session.isPresent());
        assertEquals(SESSION_ID, session.get().getSessionId());
    }

    @Test
    void shouldNotRetrieveSessionForLowerCaseHeaderName() {
        withValidSession();

        var session =
                orchSessionService.getSessionFromRequestHeaders(Map.of("session-id", SESSION_ID));
        assertTrue(session.isEmpty());
    }

    @Test
    void shouldNotRetrieveSessionWithNoHeaders() {
        var session = orchSessionService.getSessionFromRequestHeaders(Collections.emptyMap());
        assertTrue(session.isEmpty());
    }

    @Test
    void shouldNotRetrieveSessionWithNullHeaders() {
        var session = orchSessionService.getSessionFromRequestHeaders(null);
        assertTrue(session.isEmpty());
    }

    @Test
    void shouldNotRetrieveSessionWithMissingHeader() {
        var session = orchSessionService.getSessionFromRequestHeaders(Map.of("Something", "Else"));
        assertTrue(session.isEmpty());
    }

    @Test
    void shouldDeleteSessionFromDatabase() {
        var existingSession = withValidSession();
        orchSessionService.deleteSession(SESSION_ID);
        verify(table).deleteItem(existingSession);
    }

    private OrchSessionItem withValidSession() {
        OrchSessionItem existingSession = new OrchSessionItem(SESSION_ID).withTimeToLive(VALID_TTL);
        when(table.getItem(SESSION_GET_REQUEST)).thenReturn(existingSession);
        return existingSession;
    }

    private void withExpiredSession() {
        when(table.getItem(SESSION_GET_REQUEST))
                .thenReturn(new OrchSessionItem(SESSION_ID).withTimeToLive(EXPIRED_TTL));
    }

    private void withFailedDelete(OrchSessionItem orchSession) {
        doThrow(DynamoDbException.builder().message("Failed to delete item").build())
                .when(table)
                .deleteItem(orchSession);
    }

    private void withFailedUpdate() {
        doThrow(DynamoDbException.builder().message("Failed to update table").build())
                .when(table)
                .updateItem(any(OrchSessionItem.class));
    }
}
