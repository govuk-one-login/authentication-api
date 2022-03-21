package uk.gov.di.authentication.sharedtest.extensions;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.id.State;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.api.StatefulRedisConnection;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.Extension;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.authentication.shared.entity.AuthCodeExchangeData;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.services.AuthorisationCodeService.AUTH_CODE_PREFIX;
import static uk.gov.di.authentication.shared.services.ClientSessionService.CLIENT_SESSION_PREFIX;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;

public class RedisExtension
        implements Extension, BeforeAllCallback, AfterAllCallback, AfterEachCallback {

    private static final String REDIS_HOST =
            System.getenv().getOrDefault("REDIS_HOST", "localhost");
    private static final Optional<String> REDIS_PASSWORD =
            Optional.ofNullable(System.getenv("REDIS_PASSWORD"));
    private final ObjectMapper objectMapper;

    private RedisConnectionService redis;
    private RedisClient client;

    public RedisExtension(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public String createSession(String sessionId) throws IOException {
        Session session = new Session(sessionId);
        redis.saveWithExpiry(
                session.getSessionId(), objectMapper.writeValueAsString(session), 3600);
        return session.getSessionId();
    }

    public String createSession() throws IOException {
        return createSession(IdGenerator.generate());
    }

    public void addStateToRedis(State state, String sessionId) throws JsonProcessingException {
        redis.saveWithExpiry("state:" + sessionId, objectMapper.writeValueAsString(state), 3600);
    }

    public void addAuthRequestToSession(
            String clientSessionId,
            String sessionId,
            Map<String, List<String>> authRequest,
            String email)
            throws JsonProcessingException {
        Session session = objectMapper.readValue(redis.getValue(sessionId), Session.class);
        session.addClientSession(clientSessionId);
        redis.saveWithExpiry(
                session.getSessionId(), objectMapper.writeValueAsString(session), 3600);
        redis.saveWithExpiry(
                CLIENT_SESSION_PREFIX.concat(clientSessionId),
                objectMapper.writeValueAsString(
                        new ClientSession(
                                authRequest, LocalDateTime.now(), VectorOfTrust.getDefaults())),
                3600);
    }

    public void addIDTokenToSession(String clientSessionId, String idTokenHint)
            throws JsonProcessingException {
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

    public void addEmailToSession(String sessionId, String emailAddress)
            throws JsonProcessingException {
        Session session = objectMapper.readValue(redis.getValue(sessionId), Session.class);
        session.setEmailAddress(emailAddress);
        redis.saveWithExpiry(
                session.getSessionId(), objectMapper.writeValueAsString(session), 3600);
    }

    public void setSessionCredentialTrustLevel(
            String sessionId, CredentialTrustLevel credentialTrustLevel)
            throws JsonProcessingException {
        Session session = objectMapper.readValue(redis.getValue(sessionId), Session.class);
        session.setCurrentCredentialStrength(credentialTrustLevel);
        redis.saveWithExpiry(
                session.getSessionId(), objectMapper.writeValueAsString(session), 3600);
    }

    public Session getSession(String sessionId) throws JsonProcessingException {
        return objectMapper.readValue(redis.getValue(sessionId), Session.class);
    }

    public String generateAndSaveEmailCode(String email, long codeExpiryTime) {
        var code = new CodeGeneratorService().sixDigitCode();
        new CodeStorageService(redis).saveOtpCode(email, code, codeExpiryTime, VERIFY_EMAIL);

        return code;
    }

    public void generateAndSavePasswordResetCode(
            String subjectId, String code, long codeExpiryTime) {
        new CodeStorageService(redis)
                .savePasswordResetCode(subjectId, code, codeExpiryTime, RESET_PASSWORD);
    }

    public String generateAndSavePhoneNumberCode(String email, long codeExpiryTime) {
        var code = new CodeGeneratorService().sixDigitCode();
        new CodeStorageService(redis).saveOtpCode(email, code, codeExpiryTime, VERIFY_PHONE_NUMBER);

        return code;
    }

    public String generateAndSaveMfaCode(String email, long codeExpiryTime) {
        var code = new CodeGeneratorService().sixDigitCode();
        new CodeStorageService(redis).saveOtpCode(email, code, codeExpiryTime, MFA_SMS);

        return code;
    }

    public void blockPhoneCode(String email) {
        new CodeStorageService(redis).saveBlockedForEmail(email, CODE_BLOCKED_KEY_PREFIX, 10);
    }

    public void addToRedis(String key, String value, Long expiry) {
        redis.saveWithExpiry(key, value, expiry);
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
            VectorOfTrust vtr)
            throws JsonProcessingException {
        var clientSession = new ClientSession(authRequest, LocalDateTime.now(), vtr);
        redis.saveWithExpiry(
                AUTH_CODE_PREFIX.concat(authCode),
                objectMapper.writeValueAsString(
                        new AuthCodeExchangeData()
                                .setClientSessionId(clientSessionId)
                                .setEmail(email)
                                .setClientSession(clientSession)),
                300);
        redis.saveWithExpiry(
                CLIENT_SESSION_PREFIX.concat(clientSessionId),
                objectMapper.writeValueAsString(clientSession),
                300);
    }

    public void createClientSession(String clientSessionId, Map<String, List<String>> authRequest)
            throws JsonProcessingException {
        redis.saveWithExpiry(
                CLIENT_SESSION_PREFIX.concat(clientSessionId),
                objectMapper.writeValueAsString(
                        new ClientSession(
                                authRequest, LocalDateTime.now(), VectorOfTrust.getDefaults())),
                300);
    }

    @Override
    public void afterAll(ExtensionContext context) throws Exception {
        redis.close();
        client.shutdown();
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        redis = new RedisConnectionService(REDIS_HOST, 6379, false, REDIS_PASSWORD);
        RedisURI.Builder builder =
                RedisURI.builder().withHost(REDIS_HOST).withPort(6379).withSsl(false);
        if (REDIS_PASSWORD.isPresent()) builder.withPassword(REDIS_PASSWORD.get().toCharArray());
        RedisURI redisURI = builder.build();
        client = RedisClient.create(redisURI);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        flushData();
    }
}
