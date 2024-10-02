package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.orchestration.sharedtest.extensions.OrchSessionExtension;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class OrchSessionServiceIntegrationTest {

    private static final String SESSION_ID = "test-session-id";

    @RegisterExtension
    protected static final OrchSessionExtension orchSessionExtension = new OrchSessionExtension();

    @Test
    void shouldAddAndGetASession() {
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

    private void withSession() {
        orchSessionExtension.addSession(SESSION_ID);
    }
}
