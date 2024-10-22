package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.sharedtest.extensions.AuthSessionExtension;

import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;

class AuthSessionServiceIntegrationTest {
    private static final String SESSION_ID = "test-session-id";
    private static final String PREVIOUS_SESSION_ID = "test-previous-session-id";

    private final long timeToLive = 3600L;

    @RegisterExtension
    protected static final AuthSessionExtension authSessionExtension = new AuthSessionExtension();

    @Test
    void shouldAddNewSessionWithExpectedDefaultValuesWhenNoPreviousSessionIdProvided() {
        withSession();

        Optional<AuthSessionItem> retrievedSession = authSessionExtension.getSession(SESSION_ID);

        assertThat(retrievedSession.isPresent(), equalTo(true));
        assertThat(retrievedSession.get().getSessionId(), equalTo(SESSION_ID));
        assertThat(retrievedSession.get().getTtl(), equalTo(0L));
        assertThat(
                retrievedSession.get().getTimeToLive(),
                greaterThan(NowHelper.now().toInstant().getEpochSecond()));
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
        assertThat(retrievedSession.get().getTtl(), equalTo(0L));
        assertThat(
                retrievedSession.get().getTimeToLive(),
                greaterThan(NowHelper.now().toInstant().getEpochSecond()));
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
        assertThat(retrievedSession.get().getTtl(), equalTo(0L));
        assertThat(
                retrievedSession.get().getTimeToLive(),
                greaterThan(NowHelper.now().toInstant().getEpochSecond()));
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
        assertThat(retrievedSession.get().getTtl(), equalTo(0L));
        assertThat(
                retrievedSession.get().getTimeToLive(),
                greaterThan(NowHelper.now().toInstant().getEpochSecond()));
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

    @Test
    void shouldFilterOnTimeToLiveWhenTtlIsNonZero() {
        withSession();
        var expiry = NowHelper.nowPlus(timeToLive, ChronoUnit.SECONDS).toInstant().getEpochSecond();
        AuthSessionItem sessionWithTtl =
                new AuthSessionItem().withSessionId(SESSION_ID).withTtl(expiry);
        authSessionExtension.updateSession(sessionWithTtl);

        var session = authSessionExtension.getSession(SESSION_ID);

        assertTrue(session.isPresent());
        assertThat(session.get().getTtl(), equalTo(expiry));
        assertThat(session.get().getTimeToLive(), equalTo(0L));
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
