package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.LevelOfConfidence;
import uk.gov.di.authentication.sharedtest.extensions.AuthSessionExtension;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
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

        for (CodeRequestType requestType : CodeRequestType.values()) {
            assertEquals(retrievedSession.get().getCodeRequestCount(requestType), 0);
        }
        assertEquals(0, retrievedSession.get().getPasswordResetCount());
    }

    @Test
    void shouldReturnUpdatedSessionWhenItExistsAndDeletePrevious() {
        withStoredSession(PREVIOUS_SESSION_ID);

        var newSession =
                authSessionExtension.getUpdatedPreviousSessionOrCreateNew(
                        Optional.of(PREVIOUS_SESSION_ID), SESSION_ID);
        var previousSessionItem = authSessionExtension.getSession(PREVIOUS_SESSION_ID);

        assertTrue(previousSessionItem.isEmpty());
        assertThat(newSession.getSessionId(), is(SESSION_ID));
    }

    @Test
    void shouldReturnExistingSessionWhenItMatchesTheSessionIdAndPreviousSessionId() {
        var emailAddressWhichWouldntExistOnGeneratedSession = "test@example.com";
        var existingSessionItem =
                new AuthSessionItem()
                        .withSessionId(SESSION_ID)
                        .withPreviousSessionId(PREVIOUS_SESSION_ID)
                        .withEmailAddress(emailAddressWhichWouldntExistOnGeneratedSession)
                        .withTimeToLive(Instant.now().plus(10L, ChronoUnit.HOURS).toEpochMilli());
        authSessionExtension.addSession(existingSessionItem);

        var newSession =
                authSessionExtension.getUpdatedPreviousSessionOrCreateNew(
                        Optional.of(PREVIOUS_SESSION_ID), SESSION_ID);

        assertThat(newSession.getSessionId(), is(SESSION_ID));
        assertThat(newSession.getPreviousSessionId(), is(PREVIOUS_SESSION_ID));
        assertThat(
                newSession.getEmailAddress(), is(emailAddressWhichWouldntExistOnGeneratedSession));
    }

    @Test
    void shouldGenerateANewSessionWhenExistingSessionDoesNotMatchPreviousSessionId() {
        var emailAddressWhichWouldNotExistOnGeneratedSession = "test@example.com";
        var existingSessionItem =
                new AuthSessionItem()
                        .withSessionId(SESSION_ID)
                        .withPreviousSessionId("foo")
                        .withEmailAddress(emailAddressWhichWouldNotExistOnGeneratedSession)
                        .withTimeToLive(Instant.now().plus(10L, ChronoUnit.HOURS).toEpochMilli());
        authSessionExtension.addSession(existingSessionItem);

        var newSession =
                authSessionExtension.getUpdatedPreviousSessionOrCreateNew(
                        Optional.of(PREVIOUS_SESSION_ID), SESSION_ID);

        assertThat(newSession.getSessionId(), is(SESSION_ID));
        assertNull(newSession.getPreviousSessionId());
        assertNull(newSession.getEmailAddress());
    }

    @Test
    void shouldReturnNewSessionWhenPreviousDoesNotExist() {
        var previousSessionItem = authSessionExtension.getSession(PREVIOUS_SESSION_ID);

        assertTrue(previousSessionItem.isEmpty());

        var newSession =
                authSessionExtension.getUpdatedPreviousSessionOrCreateNew(
                        Optional.of(PREVIOUS_SESSION_ID), SESSION_ID);
        assertThat(newSession.getSessionId(), is(SESSION_ID));
    }

    @Test
    void shouldStoreAnUpdatedSession() {
        var session = withStoredSession(SESSION_ID);

        session.setIsNewAccount(AuthSessionItem.AccountState.EXISTING);
        session.setRequestedCredentialStrength(CredentialTrustLevel.MEDIUM_LEVEL);
        session.setRequestedLevelOfConfidence(LevelOfConfidence.MEDIUM_LEVEL);
        session.setClientId("test-client-id");
        authSessionExtension.updateSession(session);
        var updatedSession = authSessionExtension.getSession(SESSION_ID).get();
        assertThat(
                updatedSession.getIsNewAccount(), equalTo(AuthSessionItem.AccountState.EXISTING));
        assertThat(
                updatedSession.getRequestedCredentialStrength(),
                equalTo(CredentialTrustLevel.MEDIUM_LEVEL));
        assertThat(
                updatedSession.getRequestedLevelOfConfidence(),
                equalTo(LevelOfConfidence.MEDIUM_LEVEL));
        assertThat(updatedSession.getClientId(), equalTo("test-client-id"));
    }

    @Test
    void shouldReturnAPreviousSessionWithRetainedValuesAndPreviousSessionId() {
        var previousSession = withStoredSession(PREVIOUS_SESSION_ID);

        previousSession.setIsNewAccount(AuthSessionItem.AccountState.EXISTING);
        authSessionExtension.updateSession(previousSession);

        var retrievedSession =
                authSessionExtension.getUpdatedPreviousSessionOrCreateNew(
                        Optional.of(PREVIOUS_SESSION_ID), SESSION_ID);
        var retrievedPreviousSession = authSessionExtension.getSession(PREVIOUS_SESSION_ID);

        assertTrue(retrievedPreviousSession.isEmpty());
        assertThat(retrievedSession.getSessionId(), equalTo(SESSION_ID));
        assertThat(
                retrievedSession.getIsNewAccount(), equalTo(AuthSessionItem.AccountState.EXISTING));
        assertThat(retrievedSession.getPreviousSessionId(), equalTo(PREVIOUS_SESSION_ID));
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

    @Test
    void shouldStorePreservedReauthCountsForAuditMapSession() {
        var session = withStoredSession(SESSION_ID);

        var counts =
                new HashMap<CountType, Integer>() {
                    {
                        put(CountType.ENTER_EMAIL, 1);
                        put(CountType.ENTER_MFA_CODE, 3);
                    }
                };

        session.setPreservedReauthCountsForAuditMap(counts);
        authSessionExtension.updateSession(session);
        var updatedSession = authSessionExtension.getSession(SESSION_ID).get();
        assertThat(updatedSession.getPreservedReauthCountsForAuditMap(), equalTo(counts));
    }

    private AuthSessionItem withStoredSession(String sessionId) {
        authSessionExtension.addSession(sessionId);
        return authSessionExtension.getSession(sessionId).get();
    }
}
