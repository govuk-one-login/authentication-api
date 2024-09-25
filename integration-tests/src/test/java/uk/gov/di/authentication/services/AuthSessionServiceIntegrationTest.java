package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.sharedtest.extensions.AuthSessionExtension;

import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;

class AuthSessionServiceIntegrationTest {
    private static final String SESSION_ID = "test-session-id";
    private static final String PREVIOUS_SESSION_ID = "test-previous-session-id";

    @RegisterExtension
    protected static final AuthSessionExtension authSessionExtension = new AuthSessionExtension();

    @Test
    void shouldAddNewSessionWithExpectedDefaultValuesWhenNoPreviousSessionIdProvided() {
        withSession();

        Optional<AuthSessionItem> retrievedSession = authSessionExtension.getSession(SESSION_ID);

        assertThat(retrievedSession.isPresent(), equalTo(true));
        assertThat(retrievedSession.get().getSessionId(), equalTo(SESSION_ID));
        assertThat(
                retrievedSession.get().getIsNewAccount(),
                equalTo(AuthSessionItem.AccountState.UNKNOWN));
    }

    @Test
    void shouldReplaceSessionWhenPreviousSessionIdGivenAndExists() {
        withPreviousSession();
        withUpdatedPreviousSession();

        Optional<AuthSessionItem> retrievedPreviousSession =
                authSessionExtension.getSession(PREVIOUS_SESSION_ID);
        Optional<AuthSessionItem> retrievedSession = authSessionExtension.getSession(SESSION_ID);

        assertThat(retrievedPreviousSession.isPresent(), equalTo(false));
        assertThat(retrievedSession.isPresent(), equalTo(true));
        assertThat(retrievedSession.get().getSessionId(), equalTo(SESSION_ID));
    }

    @Test
    void shouldAddSessionWhenPreviousSessionIdGivenAndDoesNotExist() {
        withUpdatedPreviousSession();

        Optional<AuthSessionItem> retrievedPreviousSession =
                authSessionExtension.getSession(PREVIOUS_SESSION_ID);
        Optional<AuthSessionItem> retrievedSession = authSessionExtension.getSession(SESSION_ID);

        assertThat(retrievedPreviousSession.isPresent(), equalTo(false));
        assertThat(retrievedSession.isPresent(), equalTo(true));
        assertThat(retrievedSession.get().getSessionId(), equalTo(SESSION_ID));
        assertThat(
                retrievedSession.get().getIsNewAccount(),
                equalTo(AuthSessionItem.AccountState.UNKNOWN));
    }

    @Test
    void shouldStoreAnUpdatedSession() {
        withSession();

        var session = authSessionExtension.getSession(SESSION_ID).get();
        session.setIsNewAccount(AuthSessionItem.AccountState.EXISTING);
        authSessionExtension.updateSession(session);
        var updatedSession = authSessionExtension.getSession(SESSION_ID).get();
        assertThat(
                updatedSession.getIsNewAccount(), equalTo(AuthSessionItem.AccountState.EXISTING));
    }

    @Test
    void shouldRetainAPreviousSessionsValuesWhenSessionIdIsUpdated() {
        withPreviousSession();

        var previousSession = authSessionExtension.getSession(PREVIOUS_SESSION_ID).get();
        previousSession.setIsNewAccount(AuthSessionItem.AccountState.EXISTING);
        authSessionExtension.updateSession(previousSession);
        withUpdatedPreviousSession();

        Optional<AuthSessionItem> retrievedPreviousSession =
                authSessionExtension.getSession(PREVIOUS_SESSION_ID);
        Optional<AuthSessionItem> retrievedSession = authSessionExtension.getSession(SESSION_ID);

        assertThat(retrievedPreviousSession.isPresent(), equalTo(false));
        assertThat(retrievedSession.isPresent(), equalTo(true));
        assertThat(retrievedSession.get().getSessionId(), equalTo(SESSION_ID));
        assertThat(
                retrievedSession.get().getIsNewAccount(),
                equalTo(AuthSessionItem.AccountState.EXISTING));
    }

    @Test
    void shouldGetSessionFromRequestHeaders() {
        withSession();

        var headersWithSessionId = Map.of(SESSION_ID_HEADER, SESSION_ID);
        Optional<AuthSessionItem> retrievedSession =
                authSessionExtension.getSessionFromRequestHeaders(headersWithSessionId);
        assertThat(retrievedSession.isPresent(), equalTo(true));
        assertThat(retrievedSession.get().getSessionId(), equalTo(SESSION_ID));
    }

    private void withSession() {
        authSessionExtension.addSession(Optional.empty(), SESSION_ID);
    }

    private void withPreviousSession() {
        authSessionExtension.addSession(Optional.empty(), PREVIOUS_SESSION_ID);
    }

    private void withUpdatedPreviousSession() {
        authSessionExtension.addSession(Optional.of(PREVIOUS_SESSION_ID), SESSION_ID);
    }
}
