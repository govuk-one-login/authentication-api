package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.sharedtest.extensions.AuthSessionExtension;

import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;

class AuthSessionServiceIntegrationTest {
    private static final String SESSION_ID = "test-session-id";
    private static final String PREVIOUS_SESSION_ID = "test-previous-session-id";

    @RegisterExtension
    protected static final AuthSessionExtension authSessionExtension = new AuthSessionExtension();

    @Test
    void shouldAddNewSessionWithExpectedDefaultValues() {
        withStoredSession(SESSION_ID);

        Optional<AuthSessionItem> retrievedSession = authSessionExtension.getSession(SESSION_ID);

        assertThat(retrievedSession.isPresent(), equalTo(true));
        assertThat(retrievedSession.get().getSessionId(), equalTo(SESSION_ID));
        assertThat(
                retrievedSession.get().getIsNewAccount(),
                equalTo(AuthSessionItem.AccountState.UNKNOWN));
    }

    @Test
    void shouldReturnUpdatedSessionWhenItExistsAndDeletePrevious() {
        withStoredSession(PREVIOUS_SESSION_ID);

        AuthSessionItem previousSession =
                authSessionExtension.getUpdatedPreviousSessionOrCreateNew(
                        Optional.of(PREVIOUS_SESSION_ID),
                        SESSION_ID,
                        CredentialTrustLevel.MEDIUM_LEVEL);
        var previousSessionItem = authSessionExtension.getSession(PREVIOUS_SESSION_ID);

        assertTrue(previousSessionItem.isEmpty());
        assertThat(previousSession.getSessionId(), is(SESSION_ID));
        assertThat(
                previousSession.getCurrentCredentialStrength(),
                is(CredentialTrustLevel.MEDIUM_LEVEL));
    }

    @Test
    void shouldReturnNewSessionWhenPreviousDoesNotExist() {
        var previousSessionItem = authSessionExtension.getSession(PREVIOUS_SESSION_ID);

        assertTrue(previousSessionItem.isEmpty());

        AuthSessionItem previousSession =
                authSessionExtension.getUpdatedPreviousSessionOrCreateNew(
                        Optional.of(PREVIOUS_SESSION_ID),
                        SESSION_ID,
                        CredentialTrustLevel.MEDIUM_LEVEL);
        assertThat(previousSession.getSessionId(), is(SESSION_ID));
        assertEquals(
                CredentialTrustLevel.MEDIUM_LEVEL, previousSession.getCurrentCredentialStrength());
    }

    @Test
    void shouldStoreAnUpdatedSession() {
        var session = withStoredSession(SESSION_ID);

        session.setIsNewAccount(AuthSessionItem.AccountState.EXISTING);
        authSessionExtension.updateSession(session);
        var updatedSession = authSessionExtension.getSession(SESSION_ID).get();
        assertThat(
                updatedSession.getIsNewAccount(), equalTo(AuthSessionItem.AccountState.EXISTING));
    }

    @Test
    void shouldReturnAPreviousSessionWithRetainedValues() {
        var previousSession = withStoredSession(PREVIOUS_SESSION_ID);

        previousSession.setIsNewAccount(AuthSessionItem.AccountState.EXISTING);
        authSessionExtension.updateSession(previousSession);

        AuthSessionItem retrievedSession =
                authSessionExtension.getUpdatedPreviousSessionOrCreateNew(
                        Optional.of(PREVIOUS_SESSION_ID),
                        SESSION_ID,
                        CredentialTrustLevel.MEDIUM_LEVEL);
        var retrievedPreviousSession = authSessionExtension.getSession(PREVIOUS_SESSION_ID);

        assertTrue(retrievedPreviousSession.isEmpty());
        assertThat(retrievedSession.getSessionId(), equalTo(SESSION_ID));
        assertThat(
                retrievedSession.getIsNewAccount(), equalTo(AuthSessionItem.AccountState.EXISTING));

        assertThat(
                retrievedSession.getCurrentCredentialStrength(),
                equalTo(CredentialTrustLevel.MEDIUM_LEVEL));
    }

    @Test
    void shouldGetSessionFromRequestHeaders() {
        withStoredSession(SESSION_ID);

        var headersWithSessionId = Map.of(SESSION_ID_HEADER, SESSION_ID);
        Optional<AuthSessionItem> retrievedSession =
                authSessionExtension.getSessionFromRequestHeaders(headersWithSessionId);
        assertThat(retrievedSession.isPresent(), equalTo(true));
        assertThat(retrievedSession.get().getSessionId(), equalTo(SESSION_ID));
    }

    private AuthSessionItem withStoredSession(String sessionId) {
        authSessionExtension.addSession(sessionId);
        return authSessionExtension.getSession(sessionId).get();
    }
}
