package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.Session;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;

class AuthOrchSerializationServicesIntegrationTest {

    private static final String REDIS_HOST =
            System.getenv().getOrDefault("REDIS_HOST", "localhost");
    private static final Optional<String> REDIS_PASSWORD =
            Optional.ofNullable(System.getenv("REDIS_PASSWORD"));
    private static final String SESSION_ID = "session-id";
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
        orchSession.addClientSession(CLIENT_SESSION_ID);
        orchSessionService.storeOrUpdateSession(orchSession, SESSION_ID);
        var authSession = authSessionService.getSession(SESSION_ID).get();
        assertThat(authSession.getClientSessions(), contains(CLIENT_SESSION_ID));
    }

    @Test
    void orchCanReadFromSessionCreatedByAuth() {
        var sessionId = "some-existing-session-id";
        var authSession = new Session();
        authSession.addClientSession(CLIENT_SESSION_ID);
        authSessionService.storeOrUpdateSession(authSession, sessionId);
        var orchSession = orchSessionService.getSession(sessionId).get();
        assertThat(orchSession.getClientSessions(), contains(CLIENT_SESSION_ID));
    }

    @Test
    void authCanUpdateSharedFieldInSessionCreatedByOrch() {
        var orchSession = orchSessionService.generateSession();
        orchSessionService.storeOrUpdateSession(orchSession, SESSION_ID);
        var authSession = authSessionService.getSession(SESSION_ID).get();
        authSession.addClientSession(CLIENT_SESSION_ID);
        authSessionService.storeOrUpdateSession(authSession, SESSION_ID);
        orchSession = orchSessionService.getSession(SESSION_ID).get();
        assertThat(orchSession.getClientSessions(), contains(CLIENT_SESSION_ID));
    }

    @Test
    void orchCanUpdateSharedFieldInSessionCreatedByAuth() {
        var sessionId = "some-existing-session-id";
        var authSession = new Session();
        authSessionService.storeOrUpdateSession(authSession, sessionId);
        var orchSession = orchSessionService.getSession(sessionId).get();
        orchSession.addClientSession(CLIENT_SESSION_ID);
        orchSessionService.storeOrUpdateSession(orchSession, sessionId);
        authSession = authSessionService.getSession(sessionId).get();
        assertThat(authSession.getClientSessions(), contains(CLIENT_SESSION_ID));
    }

    @Test
    void authCanReadSessionAfterSessionIdIsUpdated() {
        var oldSessionId = SESSION_ID;
        var newSessionId = "new-session-id";
        var orchSession = orchSessionService.generateSession();
        orchSessionService.storeOrUpdateSession(orchSession, oldSessionId);
        var authSession = authSessionService.getSession(oldSessionId).get();
        authSession.addClientSession(CLIENT_SESSION_ID);
        authSessionService.storeOrUpdateSession(authSession, oldSessionId);
        orchSession = orchSessionService.getSession(oldSessionId).get();
        orchSessionService.updateWithNewSessionId(orchSession, oldSessionId, newSessionId);
        authSessionService.getSession(newSessionId).get();
        assertThat(authSession.getClientSessions(), contains(CLIENT_SESSION_ID));
    }

    @Test
    void authCanResetSharedFieldsWithoutOverridingUnsharedFields() {
        var orchSession = orchSessionService.generateSession();
        orchSession.addClientSession(CLIENT_SESSION_ID);
        orchSession.incrementProcessingIdentityAttempts();
        orchSessionService.storeOrUpdateSession(orchSession, SESSION_ID);
        var authSession = new Session();
        authSessionService.storeOrUpdateSession(authSession, SESSION_ID);
        orchSession = orchSessionService.getSession(SESSION_ID).get();
        assertThat(orchSession.getClientSessions(), is(empty()));
    }
}
