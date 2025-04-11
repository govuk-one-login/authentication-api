package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.sharedtest.extensions.OrchSessionExtension;

import java.util.ArrayList;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
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
