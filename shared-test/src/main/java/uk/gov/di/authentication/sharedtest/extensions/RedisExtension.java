package uk.gov.di.authentication.sharedtest.extensions;

import com.nimbusds.oauth2.sdk.id.State;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.api.StatefulRedisConnection;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.Extension;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.entity.mfaMethodManagement.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.services.ClientSessionService.CLIENT_SESSION_PREFIX;

public class RedisExtension
        implements Extension, BeforeAllCallback, AfterAllCallback, AfterEachCallback {
    private final ConfigurationService configurationService;
    private final CodeStorageService codeStorageService;

    private final Json objectMapper;

    private RedisConnectionService redis;
    private RedisClient client;

    public RedisExtension(Json objectMapper, ConfigurationService configurationService) {
        this.objectMapper = objectMapper;
        this.configurationService = configurationService;
        this.codeStorageService = new CodeStorageService(configurationService);
    }

    public String createSession(String sessionId) throws Json.JsonException {
        return createSession(sessionId, false, Optional.empty());
    }

    private String createSession(String sessionId, boolean isAuthenticated, Optional<String> email)
            throws Json.JsonException {
        Session session = new Session().setAuthenticated(isAuthenticated);
        email.ifPresent(session::setEmailAddress);
        redis.saveWithExpiry(sessionId, objectMapper.writeValueAsString(session), 3600);
        return sessionId;
    }

    public void setVerifiedMfaMethodType(String sessionId, MFAMethodType mfaMethodType)
            throws Json.JsonException {
        var session = objectMapper.readValue(redis.getValue(sessionId), Session.class);
        session.setVerifiedMfaMethodType(mfaMethodType);
        redis.saveWithExpiry(sessionId, objectMapper.writeValueAsString(session), 3600);
    }

    public String createSession() throws Json.JsonException {
        return createSession(IdGenerator.generate());
    }

    public String createSession(boolean isAuthenticated) throws Json.JsonException {
        return createSession(IdGenerator.generate(), isAuthenticated, Optional.empty());
    }

    public String createUnauthenticatedSessionWithEmail(String email) throws Json.JsonException {
        return createSession(IdGenerator.generate(), false, Optional.of(email));
    }

    public void createUnauthenticatedSessionWithIdAndEmail(String sessionId, String email)
            throws Json.JsonException {
        createSession(sessionId, false, Optional.of(email));
    }

    public String createAuthenticatedSessionWithEmail(String email) throws Json.JsonException {
        return createSession(IdGenerator.generate(), true, Optional.of(email));
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
        redis.saveWithExpiry(sessionId, objectMapper.writeValueAsString(session), 3600);
    }

    public void incrementPasswordCount(String email) {
        codeStorageService.increaseIncorrectPasswordCount(email);
    }

    public void incrementPasswordCountReauthJourney(String email) {
        codeStorageService.increaseIncorrectPasswordCountReauthJourney(email);
    }

    public void incrementEmailCount(String email) {
        codeStorageService.increaseIncorrectEmailCount(email);
    }

    public void addAuthRequestToSession(
            String clientSessionId,
            String sessionId,
            Map<String, List<String>> authRequest,
            String clientName)
            throws Json.JsonException {
        Session session = objectMapper.readValue(redis.getValue(sessionId), Session.class);
        session.addClientSession(clientSessionId);
        redis.saveWithExpiry(sessionId, objectMapper.writeValueAsString(session), 3600);
        redis.saveWithExpiry(
                CLIENT_SESSION_PREFIX.concat(clientSessionId),
                objectMapper.writeValueAsString(
                        new ClientSession(
                                authRequest,
                                LocalDateTime.now(),
                                VectorOfTrust.getDefaults(),
                                clientName)),
                3600);
    }

    public void addEmailToSession(String sessionId, String emailAddress) throws Json.JsonException {
        Session session = objectMapper.readValue(redis.getValue(sessionId), Session.class);
        session.setEmailAddress(emailAddress);
        redis.saveWithExpiry(sessionId, objectMapper.writeValueAsString(session), 3600);
    }

    public void setSessionCredentialTrustLevel(
            String sessionId, CredentialTrustLevel credentialTrustLevel) throws Json.JsonException {
        Session session = objectMapper.readValue(redis.getValue(sessionId), Session.class);
        session.setCurrentCredentialStrength(credentialTrustLevel);
        redis.saveWithExpiry(sessionId, objectMapper.writeValueAsString(session), 3600);
    }

    public Session getSession(String sessionId) throws Json.JsonException {
        return objectMapper.readValue(redis.getValue(sessionId), Session.class);
    }

    public void incrementSessionCodeRequestCount(
            String sessionId, NotificationType notificationType, JourneyType journeyType)
            throws Json.JsonException {
        var session =
                objectMapper
                        .readValue(redis.getValue(sessionId), Session.class)
                        .incrementCodeRequestCount(notificationType, journeyType);
        redis.saveWithExpiry(sessionId, objectMapper.writeValueAsString(session), 3600);
    }

    public String generateAndSaveEmailCode(String email, long codeExpiryTime) {
        var code = new CodeGeneratorService().sixDigitCode();
        codeStorageService.saveOtpCode(email, code, codeExpiryTime, VERIFY_EMAIL);

        return code;
    }

    public String generateAndSaveEmailCode(
            String email, long codeExpiryTime, NotificationType notificationType) {
        var code = new CodeGeneratorService().sixDigitCode();
        codeStorageService.saveOtpCode(email, code, codeExpiryTime, notificationType);

        return code;
    }

    public String generateAndSavePhoneNumberCode(String email, long codeExpiryTime) {
        var code = new CodeGeneratorService().sixDigitCode();
        codeStorageService.saveOtpCode(email, code, codeExpiryTime, VERIFY_PHONE_NUMBER);

        return code;
    }

    public String generateAndSaveMfaCode(String email, long codeExpiryTime) {
        var code = new CodeGeneratorService().sixDigitCode();
        codeStorageService.saveOtpCode(email, code, codeExpiryTime, MFA_SMS);

        return code;
    }

    public Optional<String> getMfaCode(String email, NotificationType notificationType) {
        return codeStorageService.getOtpCode(email, notificationType);
    }

    public void blockMfaCodesForEmail(String email, String codeBlockedKeyPrefix) {
        var codeBlockedTime = 10;
        codeStorageService.saveBlockedForEmail(email, codeBlockedKeyPrefix, codeBlockedTime);
    }

    public boolean isBlockedMfaCodesForEmail(String email, String codeBlockedKeyPrefix) {
        return codeStorageService.isBlockedForEmail(email, codeBlockedKeyPrefix);
    }

    public int getMfaCodeAttemptsCount(String email) {
        return codeStorageService.getIncorrectMfaCodeAttemptsCount(email);
    }

    public int getMfaCodeAttemptsCount(String email, MFAMethodType mfaMethodType) {
        return codeStorageService.getIncorrectMfaCodeAttemptsCount(email, mfaMethodType);
    }

    public void increaseMfaCodeAttemptsCount(String email, MFAMethodType mfaMethodType) {
        codeStorageService.increaseIncorrectMfaCodeAttemptsCount(email, mfaMethodType);
    }

    public void increaseMfaCodeAttemptsCount(String email) {
        codeStorageService.increaseIncorrectMfaCodeAttemptsCount(email);
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

    public void createClientSession(
            String clientSessionId, String clientName, Map<String, List<String>> authRequest)
            throws Json.JsonException {
        redis.saveWithExpiry(
                CLIENT_SESSION_PREFIX.concat(clientSessionId),
                objectMapper.writeValueAsString(
                        new ClientSession(
                                authRequest,
                                LocalDateTime.now(),
                                VectorOfTrust.getDefaults(),
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
    public void afterAll(ExtensionContext context) throws Exception {
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
        client = RedisClient.create(redisURI);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        flushData();
    }
}
