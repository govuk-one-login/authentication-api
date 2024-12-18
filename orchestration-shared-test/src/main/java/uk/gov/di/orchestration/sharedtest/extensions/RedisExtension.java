package uk.gov.di.orchestration.sharedtest.extensions;

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.api.StatefulRedisConnection;
import org.junit.jupiter.api.extension.*;
import uk.gov.di.orchestration.shared.entity.*;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.services.AuthorisationCodeService.AUTH_CODE_PREFIX;
import static uk.gov.di.orchestration.shared.services.ClientSessionService.CLIENT_SESSION_PREFIX;

public class RedisExtension
        implements Extension, BeforeAllCallback, AfterAllCallback, AfterEachCallback {
    private final ConfigurationService configurationService;

    private final Json objectMapper;

    private RedisConnectionService redis;
    private RedisClient client;

    public RedisExtension(Json objectMapper, ConfigurationService configurationService) {
        this.objectMapper = objectMapper;
        this.configurationService = configurationService;
    }

    public String createSession(String sessionId) throws Json.JsonException {
        return createSession(sessionId, false, Optional.empty());
    }

    private String createSession(String sessionId, boolean isAuthenticated, Optional<String> email)
            throws Json.JsonException {
        Session session = new Session(sessionId).setAuthenticated(isAuthenticated);
        email.ifPresent(session::setEmailAddress);
        redis.saveWithExpiry(
                session.getSessionId(), objectMapper.writeValueAsString(session), 3600);
        return session.getSessionId();
    }

    public void setVerifiedMfaMethodType(String sessionId, MFAMethodType mfaMethodType)
            throws Json.JsonException {
        var session = objectMapper.readValue(redis.getValue(sessionId), Session.class);
        session.setVerifiedMfaMethodType(mfaMethodType);
        redis.saveWithExpiry(
                session.getSessionId(), objectMapper.writeValueAsString(session), 3600);
    }

    public String createSession() throws Json.JsonException {
        return createSession(IdGenerator.generate());
    }

    public String createSession(boolean isAuthenticated) throws Json.JsonException {
        return createSession(IdGenerator.generate(), isAuthenticated, Optional.empty());
    }

    public void addDocAppSubjectIdToClientSession(Subject subject, String clientSessionId)
            throws Json.JsonException {
        var clientSession =
                objectMapper.readValue(
                        redis.getValue(CLIENT_SESSION_PREFIX.concat(clientSessionId)),
                        ClientSession.class);
        clientSession.setDocAppSubjectId(subject);
        redis.saveWithExpiry(
                CLIENT_SESSION_PREFIX.concat(clientSessionId),
                objectMapper.writeValueAsString(clientSession),
                3600);
    }

    public void addStateToRedis(State state, String sessionId) throws Json.JsonException {
        addStateToRedis("state:", state, sessionId);
    }

    public void addStateToRedis(String prefix, State state, String sessionId)
            throws Json.JsonException {
        redis.saveWithExpiry(prefix + sessionId, objectMapper.writeValueAsString(state), 3600);
    }

    public void addClientSessionAndStateToRedis(State state, String clientSessionId) {
        redis.saveWithExpiry("state:" + state.getValue(), clientSessionId, 3600);
    }

    public void addClientSessionIdToSession(String clientSessionId, String sessionId)
            throws Json.JsonException {
        Session session = objectMapper.readValue(redis.getValue(sessionId), Session.class);
        session.addClientSession(clientSessionId);
        redis.saveWithExpiry(
                session.getSessionId(), objectMapper.writeValueAsString(session), 3600);
    }

    public void incrementInitialProcessingIdentityAttemptsInSession(String sessionId)
            throws Json.JsonException {
        Session session = objectMapper.readValue(redis.getValue(sessionId), Session.class);
        session.incrementProcessingIdentityAttempts();
        redis.saveWithExpiry(
                session.getSessionId(), objectMapper.writeValueAsString(session), 3600);
    }

    public void addAuthRequestToSession(
            String clientSessionId,
            String sessionId,
            Map<String, List<String>> authRequest,
            String clientName)
            throws Json.JsonException {
        Session session = objectMapper.readValue(redis.getValue(sessionId), Session.class);
        session.addClientSession(clientSessionId);
        redis.saveWithExpiry(
                session.getSessionId(), objectMapper.writeValueAsString(session), 3600);
        redis.saveWithExpiry(
                CLIENT_SESSION_PREFIX.concat(clientSessionId),
                objectMapper.writeValueAsString(
                        new ClientSession(
                                authRequest,
                                LocalDateTime.now(),
                                List.of(VectorOfTrust.getDefaults()),
                                clientName)),
                3600);
    }

    public void addIDTokenToSession(String clientSessionId, String idTokenHint)
            throws Json.JsonException {
        ClientSession clientSession =
                objectMapper.readValue(
                        redis.getValue(CLIENT_SESSION_PREFIX.concat(clientSessionId)),
                        ClientSession.class);
        clientSession.setIdTokenHint(idTokenHint);
        redis.saveWithExpiry(
                CLIENT_SESSION_PREFIX.concat(clientSessionId),
                objectMapper.writeValueAsString(clientSession),
                3600);
    }

    public void addEmailToSession(String sessionId, String emailAddress) throws Json.JsonException {
        Session session = objectMapper.readValue(redis.getValue(sessionId), Session.class);
        session.setEmailAddress(emailAddress);
        redis.saveWithExpiry(
                session.getSessionId(), objectMapper.writeValueAsString(session), 3600);
    }

    public void addBrowserSesssionIdToSession(String sessionId, String browserSessionId)
            throws Json.JsonException {
        Session session = objectMapper.readValue(redis.getValue(sessionId), Session.class);
        session.setBrowserSessionId(browserSessionId);
        redis.saveWithExpiry(
                session.getSessionId(), objectMapper.writeValueAsString(session), 3600);
    }

    public void setSessionCredentialTrustLevel(
            String sessionId, CredentialTrustLevel credentialTrustLevel) throws Json.JsonException {
        Session session = objectMapper.readValue(redis.getValue(sessionId), Session.class);
        session.setCurrentCredentialStrength(credentialTrustLevel);
        redis.saveWithExpiry(
                session.getSessionId(), objectMapper.writeValueAsString(session), 3600);
    }

    public Session getSession(String sessionId) throws Json.JsonException {
        return objectMapper.readValue(redis.getValue(sessionId), Session.class);
    }

    public void addToRedis(String key, String value, Long expiry) {
        redis.saveWithExpiry(key, value, expiry);
    }

    public String getFromRedis(String key) {
        return redis.getValue(key);
    }

    public void flushData() {
        try (StatefulRedisConnection<String, String> connection = client.connect()) {
            connection.sync().flushall();
        }
    }

    public void addAuthCodeAndCreateClientSession(
            String authCode,
            String clientSessionId,
            String email,
            Map<String, List<String>> authRequest,
            List<VectorOfTrust> vtrList,
            String clientName,
            Long authTime)
            throws Json.JsonException {
        var clientSession =
                new ClientSession(authRequest, LocalDateTime.now(), vtrList, clientName);
        redis.saveWithExpiry(
                AUTH_CODE_PREFIX.concat(authCode),
                objectMapper.writeValueAsString(
                        new AuthCodeExchangeData()
                                .setClientSessionId(clientSessionId)
                                .setEmail(email)
                                .setClientSession(clientSession)
                                .setAuthTime(authTime)),
                300);

        redis.saveWithExpiry(
                CLIENT_SESSION_PREFIX.concat(clientSessionId),
                objectMapper.writeValueAsString(clientSession),
                300);
    }

    public void createClientSession(
            String clientSessionId, String clientName, Map<String, List<String>> authRequest)
            throws Json.JsonException {
        redis.saveWithExpiry(
                CLIENT_SESSION_PREFIX.concat(clientSessionId),
                objectMapper.writeValueAsString(
                        new ClientSession(
                                authRequest,
                                LocalDateTime.now(),
                                List.of(VectorOfTrust.getDefaults()),
                                clientName)),
                300);
    }

    public ClientSession getClientSession(String clientSessionId) {
        try {
            var result = redis.getValue(CLIENT_SESSION_PREFIX.concat(clientSessionId));
            return objectMapper.readValue(result, ClientSession.class);
        } catch (Json.JsonException e) {
            throw new RuntimeException(e);
        }
    }

    public void createClientSession(String clientSessionId, ClientSession clientSession)
            throws Json.JsonException {
        redis.saveWithExpiry(
                CLIENT_SESSION_PREFIX.concat(clientSessionId),
                objectMapper.writeValueAsString(clientSession),
                300);
    }

    @Override
    public void afterAll(ExtensionContext context) {
        redis.close();
        client.shutdown();
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        redis = new RedisConnectionService(configurationService);
        RedisURI.Builder builder =
                RedisURI.builder()
                        .withHost(configurationService.getRedisHost())
                        .withPort(configurationService.getRedisPort())
                        .withSsl(configurationService.getUseRedisTLS());
        configurationService
                .getRedisPassword()
                .ifPresent(redisPassword -> builder.withPassword(redisPassword.toCharArray()));
        RedisURI redisURI = builder.build();
        if (client != null) {
            client.shutdown();
        }
        client = RedisClient.create(redisURI);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        flushData();
    }
}
