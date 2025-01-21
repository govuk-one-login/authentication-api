package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.Session;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

class AuthOrchSerializationServicesIntegrationTest {

    private static final String REDIS_HOST =
            System.getenv().getOrDefault("REDIS_HOST", "localhost");
    private static final Optional<String> REDIS_PASSWORD =
            Optional.ofNullable(System.getenv("REDIS_PASSWORD"));
    private static final String BROWSER_SESSION_ID = "browser-session-id";
    private static final String CLIENT_SESSION_ID = "client-session-id";

    private uk.gov.di.orchestration.shared.services.SessionService orchSessionService;
    private uk.gov.di.authentication.shared.services.SessionService authSessionService;

    @BeforeEach
    void setup() {
        var orchConfigurationService =
                uk.gov.di.orchestration.shared.services.ConfigurationService.getInstance();
        var authConfigurationService =
                uk.gov.di.authentication.shared.services.ConfigurationService.getInstance();
        var orchRedisConnectionService =
                new uk.gov.di.orchestration.shared.services.RedisConnectionService(
                        REDIS_HOST, 6379, false, REDIS_PASSWORD, false);
        var authRedisConnectionService =
                new uk.gov.di.authentication.shared.services.RedisConnectionService(
                        REDIS_HOST, 6379, false, REDIS_PASSWORD, false);

        orchSessionService =
                new uk.gov.di.orchestration.shared.services.SessionService(
                        orchConfigurationService, orchRedisConnectionService);
        authSessionService =
                new uk.gov.di.authentication.shared.services.SessionService(
                        authConfigurationService, authRedisConnectionService);
    }

    @Test
    void authCanReadFromSessionCreatedByOrch() {
        var orchSession = orchSessionService.generateSession();
        var sessionId = orchSession.getSessionId();
        orchSession.addClientSession(CLIENT_SESSION_ID);
        orchSessionService.storeOrUpdateSession(orchSession);
        var authSession = authSessionService.getSession(sessionId).get();
        assertThat(authSession.getClientSessions(), contains(CLIENT_SESSION_ID));
    }

    @Test
    void orchCanReadFromSessionCreatedByAuth() {
        var sessionId = "some-existing-session-id";
        var authSession = new Session(sessionId);
        authSession.addClientSession(CLIENT_SESSION_ID);
        authSessionService.storeOrUpdateSession(authSession);
        var orchSession = orchSessionService.getSession(sessionId).get();
        assertThat(orchSession.getClientSessions(), contains(CLIENT_SESSION_ID));
    }

    @Test
    void authCanUpdateSharedFieldInSessionCreatedByOrch() {
        var orchSession = orchSessionService.generateSession();
        var sessionId = orchSession.getSessionId();
        orchSessionService.storeOrUpdateSession(orchSession);
        var authSession = authSessionService.getSession(sessionId).get();
        authSession.addClientSession(CLIENT_SESSION_ID);
        authSessionService.storeOrUpdateSession(authSession);
        orchSession = orchSessionService.getSession(sessionId).get();
        assertThat(orchSession.getClientSessions(), contains(CLIENT_SESSION_ID));
    }

    @Test
    void orchCanUpdateSharedFieldInSessionCreatedByAuth() {
        var sessionId = "some-existing-session-id";
        var authSession = new Session(sessionId);
        authSessionService.storeOrUpdateSession(authSession);
        var orchSession = orchSessionService.getSession(sessionId).get();
        orchSession.addClientSession(CLIENT_SESSION_ID);
        orchSessionService.storeOrUpdateSession(orchSession);
        authSession = authSessionService.getSession(sessionId).get();
        assertThat(authSession.getClientSessions(), contains(CLIENT_SESSION_ID));
    }

    @Test
    void orchCanReadUnsharedFieldAfterAuthUpdatesSession() {
        var orchSession = orchSessionService.generateSession();
        var sessionId = orchSession.getSessionId();
        orchSession.incrementProcessingIdentityAttempts();
        orchSessionService.storeOrUpdateSession(orchSession);
        var authSession = authSessionService.getSession(sessionId).get();
        authSession.addClientSession(CLIENT_SESSION_ID);
        authSessionService.storeOrUpdateSession(authSession);
        orchSession = orchSessionService.getSession(sessionId).get();
        assertThat(orchSession.getProcessingIdentityAttempts(), is(equalTo(1)));
    }

    @Test
    void authCanReadUnsharedFieldAfterOrchUpdatesSession() {
        var sessionId = "some-existing-session-id";
        var authSession = new Session(sessionId);
        authSession.incrementPasswordResetCount();
        authSession.incrementPasswordResetCount();
        authSession.incrementPasswordResetCount();
        authSessionService.storeOrUpdateSession(authSession);
        var orchSession = orchSessionService.getSession(sessionId).get();
        orchSession.addClientSession(CLIENT_SESSION_ID);
        orchSessionService.storeOrUpdateSession(orchSession);
        authSession = authSessionService.getSession(sessionId).get();
        assertThat(authSession.getPasswordResetCount(), is(equalTo(3)));
    }

    @Test
    void authCanReadSessionAfterSessionIdIsUpdated() {
        var orchSession = orchSessionService.generateSession();
        var originalSessionId = orchSession.getSessionId();
        orchSessionService.storeOrUpdateSession(orchSession);
        var authSession = authSessionService.getSession(originalSessionId).get();
        authSession.addClientSession(CLIENT_SESSION_ID);
        authSessionService.storeOrUpdateSession(authSession);
        orchSession = orchSessionService.getSession(originalSessionId).get();
        orchSessionService.updateWithNewSessionId(orchSession);
        var newSessionId = orchSession.getSessionId();
        authSessionService.getSession(newSessionId).get();
        assertThat(authSession.getClientSessions(), contains(CLIENT_SESSION_ID));
    }

    @Test
    void authCanResetSharedFieldsWithoutOverridingUnsharedFields() {
        var orchSession = orchSessionService.generateSession();
        var sessionId = orchSession.getSessionId();
        orchSession.addClientSession(CLIENT_SESSION_ID);
        orchSession.incrementProcessingIdentityAttempts();
        orchSessionService.storeOrUpdateSession(orchSession);
        var authSession = new Session(sessionId);
        authSessionService.storeOrUpdateSession(authSession);
        orchSession = orchSessionService.getSession(sessionId).get();
        assertThat(orchSession.getClientSessions(), is(empty()));
        assertThat(orchSession.getProcessingIdentityAttempts(), is(equalTo(1)));
    }
}
