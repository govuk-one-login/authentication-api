package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.sharedtest.extensions.OrchSessionExtension;

import java.util.ArrayList;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OrchSessionServiceIntegrationTest {

    private static final String SESSION_ID = "test-session-id";
    private static final String PREVIOUS_SESSION_ID = "previous-session-id";

    @RegisterExtension
    protected static final OrchSessionExtension orchSessionExtension = new OrchSessionExtension();

    @Test
    void shouldAddAndGetASessionWithDefaultAccountState() {
        withSession();

        var session = orchSessionExtension.getSession(SESSION_ID).get();

        assertThat(session.getSessionId(), equalTo(SESSION_ID));
    }

    @Test
    void shouldReturnEmptyIfSessionNotFound() {
        withSession();

        var session = orchSessionExtension.getSession("invalid-session-id");

        assertThat(session, equalTo(Optional.empty()));
    }

    @Test
    void shouldAddNewSessionIfPreviousIdEmpty() {
        orchSessionExtension.addOrUpdateSessionId(Optional.empty(), SESSION_ID);

        var retrievedSession = orchSessionExtension.getSession(SESSION_ID);
        assertTrue(retrievedSession.isPresent());
        assertThat(
                retrievedSession.get().getIsNewAccount(),
                equalTo(OrchSessionItem.AccountState.UNKNOWN));
        assertThat(retrievedSession.get().getClientSessions(), equalTo(new ArrayList<>()));
    }

    @Test
    void shouldUpdatePreviousSessionWithNewId() {
        withPreviousExistingAccountSessionWithOneIdentityAttempt();
        assertTrue(orchSessionExtension.getSession(PREVIOUS_SESSION_ID).isPresent());

        orchSessionExtension.addOrUpdateSessionId(Optional.of(PREVIOUS_SESSION_ID), SESSION_ID);
        var previousSession = orchSessionExtension.getSession(PREVIOUS_SESSION_ID);
        var retrievedSession = orchSessionExtension.getSession(SESSION_ID);

        assertTrue(previousSession.isEmpty());
        assertTrue(retrievedSession.isPresent());
        assertThat(
                retrievedSession.get().getIsNewAccount(),
                equalTo(OrchSessionItem.AccountState.EXISTING));
        assertThat(retrievedSession.get().getProcessingIdentityAttempts(), equalTo(0));
    }

    @Test
    void shouldGetSessionsByInternalCommonSubjectId() {
        createSessionWithIcsid("test-session-1", "same-icsid");
        createSessionWithIcsid("test-session-2", "same-icsid");
        createSessionWithIcsid("test-session-3", "different-icsid");

        var sessions = orchSessionExtension.getSessionsByInternalCommonSubjectId("same-icsid");
        assertThat(sessions, hasSize(2));
        var sessionIds = sessions.stream().map(OrchSessionItem::getSessionId).toList();
        assertThat(sessionIds, containsInAnyOrder("test-session-1", "test-session-2"));
        assertThat(sessionIds, not(contains("test-session-3")));
    }

    private void createSessionWithIcsid(String sessionId, String icsid) {
        orchSessionExtension.addSession(
                new OrchSessionItem(sessionId).withInternalCommonSubjectId(icsid));
    }

    private void withSession() {
        orchSessionExtension.addSession(new OrchSessionItem(SESSION_ID));
    }

    private void withPreviousExistingAccountSessionWithOneIdentityAttempt() {
        var session =
                new OrchSessionItem(PREVIOUS_SESSION_ID)
                        .withAccountState(OrchSessionItem.AccountState.EXISTING);
        session.incrementProcessingIdentityAttempts();
        orchSessionExtension.addSession(session);
    }
}
