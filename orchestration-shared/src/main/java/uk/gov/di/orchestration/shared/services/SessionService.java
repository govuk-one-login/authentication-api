package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.helpers.JsonUpdateHelper;
import uk.gov.di.orchestration.shared.serialization.Json;

import java.util.Map;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.orchestration.shared.helpers.InputSanitiser.sanitiseBase64;
import static uk.gov.di.orchestration.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;
import static uk.gov.di.orchestration.shared.helpers.RequestHeaderHelper.headersContainValidHeader;

public class SessionService {

    private static final Logger LOG = LogManager.getLogger(SessionService.class);

    private static final Json OBJECT_MAPPER = SerializationService.getInstance();

    private final ConfigurationService configurationService;
    private final RedisConnectionService redisConnectionService;
    private final CookieHelper cookieHelper;

    public SessionService(
            ConfigurationService configurationService,
            RedisConnectionService redisConnectionService) {
        this.configurationService = configurationService;
        this.redisConnectionService = redisConnectionService;
        this.cookieHelper = new CookieHelper();
    }

    public SessionService(ConfigurationService configurationService) {
        this(
                configurationService,
                new RedisConnectionService(
                        configurationService.getRedisHost(),
                        configurationService.getRedisPort(),
                        configurationService.getUseRedisTLS(),
                        configurationService.getRedisPassword()));
    }

    public Session generateSession() {
        Session session = new Session(IdGenerator.generate());
        session.setBrowserSessionId(IdGenerator.generate());

        return session;
    }

    public Session copySessionForMaxAge(Session previousSession, String newSessionId) {
        var copiedSession = new Session(previousSession);
        copiedSession.setSessionId(newSessionId);
        copiedSession.setBrowserSessionId(IdGenerator.generate());
        copiedSession.setAuthenticated(false).setCurrentCredentialStrength(null);
        copiedSession.resetClientSessions();
        return copiedSession;
    }

    public void storeOrUpdateSession(Session session) {
        storeOrUpdateSession(session, session.getSessionId());
    }

    private void storeOrUpdateSession(Session session, String oldSessionId) {
        try {
            var newSession = OBJECT_MAPPER.writeValueAsString(session);
            if (redisConnectionService.keyExists(oldSessionId)) {
                var oldSession = redisConnectionService.getValue(oldSessionId);
                newSession = JsonUpdateHelper.updateJson(oldSession, newSession);
            }

            redisConnectionService.saveWithExpiry(
                    session.getSessionId(), newSession, configurationService.getSessionExpiry());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void updateWithNewSessionId(Session session) {
        try {
            String oldSessionId = session.getSessionId();
            session.setSessionId(IdGenerator.generate());
            session.resetProcessingIdentityAttempts();
            storeOrUpdateSession(session, oldSessionId);
            redisConnectionService.deleteValue(oldSessionId);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void updateWithNewSessionId(Session session, String newSessionId) {
        try {
            String oldSessionId = session.getSessionId();
            session.setSessionId(newSessionId);
            session.resetProcessingIdentityAttempts();
            storeOrUpdateSession(session, oldSessionId);
            redisConnectionService.deleteValue(oldSessionId);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Optional<Session> getSessionFromRequestHeaders(Map<String, String> headers) {
        if (!headersContainValidHeader(
                headers, SESSION_ID_HEADER, configurationService.getHeadersCaseInsensitive())) {
            LOG.warn("Headers are missing Session-Id header");
            return Optional.empty();
        }
        String sessionId =
                getHeaderValueFromHeaders(
                        headers,
                        SESSION_ID_HEADER,
                        configurationService.getHeadersCaseInsensitive());
        if (sessionId == null) {
            LOG.warn("Value not found for Session-Id header");
            return Optional.empty();
        }

        return sanitiseBase64(sessionId)
                .flatMap(
                        id -> {
                            try {
                                return getSession(id);
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    public Optional<Session> getSessionFromSessionCookie(Map<String, String> headers) {
        try {
            Optional<CookieHelper.SessionCookieIds> ids = cookieHelper.parseSessionCookie(headers);
            return ids.flatMap(s -> getSession(s.getSessionId()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void deleteStoredSession(String sessionId) {
        redisConnectionService.deleteValue(sessionId);
    }

    public Optional<Session> getSession(String sessionId) {
        String serializedSession = redisConnectionService.getValue(sessionId);
        return Optional.ofNullable(serializedSession)
                .map(s -> OBJECT_MAPPER.readValueUnchecked(s, Session.class));
    }
}
