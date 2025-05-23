package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.Session;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class AuthOrchSerializationServicesIntegrationTest {

    private static final String REDIS_HOST =
            System.getenv().getOrDefault("REDIS_HOST", "localhost");
    private static final Optional<String> REDIS_PASSWORD =
            Optional.ofNullable(System.getenv("REDIS_PASSWORD"));
    private static final String SESSION_ID = "session-id";

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
    void orchCanReadSessionCreatedByAuth() {
        var sessionId = "some-existing-session-id";
        var authSession = new Session();
        authSessionService.storeOrUpdateSession(authSession, sessionId);
        assertDoesNotThrow(
                () -> {
                    orchSessionService.getSession(sessionId).get();
                });
    }

    @Test
    void authCanUpdateSharedFieldInSessionCreatedByOrch() {
        var orchSession = orchSessionService.generateSession();
        orchSessionService.storeOrUpdateSession(orchSession, SESSION_ID);
        var authSession = authSessionService.getSession(SESSION_ID).get();
        authSessionService.storeOrUpdateSession(authSession, SESSION_ID);
        assertDoesNotThrow(
                () -> {
                    orchSessionService.getSession(SESSION_ID).get();
                });
    }

    @Test
    void authCanReadSessionAfterSessionIdIsUpdated() {
        var oldSessionId = SESSION_ID;
        var newSessionId = "new-session-id";
        var orchSession = orchSessionService.generateSession();
        orchSessionService.storeOrUpdateSession(orchSession, oldSessionId);
        var authSession = authSessionService.getSession(oldSessionId).get();
        authSessionService.storeOrUpdateSession(authSession, oldSessionId);
        orchSession = orchSessionService.getSession(oldSessionId).get();
        orchSessionService.updateWithNewSessionId(orchSession, oldSessionId, newSessionId);
        authSessionService.getSession(newSessionId).get();
        assertNotNull(authSession);
    }

    @Test
    void authAndOrchCanReadTheSessionWithoutError() {
        var orchSession = orchSessionService.generateSession();
        orchSessionService.storeOrUpdateSession(orchSession, SESSION_ID);
        var authSession = new Session();
        authSessionService.storeOrUpdateSession(authSession, SESSION_ID);
        orchSession = orchSessionService.getSession(SESSION_ID).get();
        assertNotNull(orchSession);
    }
}
