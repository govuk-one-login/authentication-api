package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.sharedtest.extensions.AuthSessionExtension;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class AuthSessionServiceIntegrationTest {
    private static final String SESSION_ID = "test-session-id";
    private static final String PREVIOUS_SESSION_ID = "test-previous-session-id";

    @RegisterExtension
    protected static final AuthSessionExtension authSessionExtension = new AuthSessionExtension();

    @Test
    void shouldAddNewSessionWithExpectedDefaultValuesWhenNoPreviousSessionIdProvided() {
        authSessionExtension.addSession(Optional.empty(), SESSION_ID);

        Optional<AuthSessionItem> retrievedSession = authSessionExtension.getSession(SESSION_ID);

        assertThat(retrievedSession.isPresent(), equalTo(true));
        assertThat(retrievedSession.get().getSessionId(), equalTo(SESSION_ID));
        assertThat(
                retrievedSession.get().getIsNewAccount(),
                equalTo(AuthSessionItem.AccountState.UNKNOWN));
    }

    @Test
    void shouldReplaceSessionWhenPreviousSessionIdGivenAndExists() {
        authSessionExtension.addSession(Optional.empty(), PREVIOUS_SESSION_ID);
        authSessionExtension.addSession(Optional.of(PREVIOUS_SESSION_ID), SESSION_ID);

        Optional<AuthSessionItem> retrievedPreviousSession =
                authSessionExtension.getSession(PREVIOUS_SESSION_ID);
        Optional<AuthSessionItem> retrievedSession = authSessionExtension.getSession(SESSION_ID);

        assertThat(retrievedPreviousSession.isPresent(), equalTo(false));
        assertThat(retrievedSession.isPresent(), equalTo(true));
        assertThat(retrievedSession.get().getSessionId(), equalTo(SESSION_ID));
    }

    @Test
    void shouldAddSessionWhenPreviousSessionIdGivenAndDoesNotExist() {
        authSessionExtension.addSession(Optional.of(PREVIOUS_SESSION_ID), SESSION_ID);

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
}
