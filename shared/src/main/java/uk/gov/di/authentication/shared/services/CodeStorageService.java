package uk.gov.di.authentication.shared.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.helpers.HashHelper;

import java.util.Optional;

import static java.lang.String.format;

public class CodeStorageService {

    private static final Logger LOGGER = LoggerFactory.getLogger(CodeStorageService.class);

    private final RedisConnectionService redisConnectionService;
    private static final String EMAIL_KEY_PREFIX = "email-code:";
    private static final String PHONE_NUMBER_KEY_PREFIX = "phone-number-code:";
    private static final String MFA_KEY_PREFIX = "mfa-code:";
    private static final String CODE_BLOCKED_KEY_PREFIX = "code-blocked:";
    private static final String CODE_BLOCKED_VALUE = "blocked";
    private static final String RESET_PASSWORD_KEY_PREFIX = "reset-password-code:";

    public CodeStorageService(RedisConnectionService redisConnectionService) {
        this.redisConnectionService = redisConnectionService;
    }

    public void saveCodeBlockedForSession(String email, String sessionId, long codeBlockedTime) {
        String encodedHash = HashHelper.hashSha256String(email);
        String key = CODE_BLOCKED_KEY_PREFIX + encodedHash + sessionId;
        try {
            redisConnectionService.saveWithExpiry(key, CODE_BLOCKED_VALUE, codeBlockedTime);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void saveOtpCode(
            String emailAddress,
            String code,
            long codeExpiryTime,
            NotificationType notificationType) {
        String hashedEmailAddress = HashHelper.hashSha256String(emailAddress);
        String prefix = getPrefixForNotificationType(notificationType);
        String key = prefix + hashedEmailAddress;
        try {
            redisConnectionService.saveWithExpiry(key, code, codeExpiryTime);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void savePasswordResetCode(
            String subjectId, String code, long codeExpiryTime, NotificationType notificationType) {
        String prefix = getPrefixForNotificationType(notificationType);
        String key = prefix + code;
        try {
            redisConnectionService.saveWithExpiry(key, subjectId, codeExpiryTime);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Optional<String> getSubjectWithPasswordResetCode(String code) {
        return Optional.of(redisConnectionService.getValue(RESET_PASSWORD_KEY_PREFIX + code));
    }

    public void deleteSubjectWithPasswordResetCode(String code) {
        long numberOfKeysRemoved =
                redisConnectionService.deleteValue(RESET_PASSWORD_KEY_PREFIX + code);
        if (numberOfKeysRemoved == 0) {
            LOGGER.info(format("No key was deleted for code: %s", code));
        }
    }

    public boolean isCodeBlockedForSession(String emailAddress, String sessionId) {
        return redisConnectionService.getValue(
                        CODE_BLOCKED_KEY_PREFIX
                                + HashHelper.hashSha256String(emailAddress)
                                + sessionId)
                != null;
    }

    public Optional<String> getOtpCode(String emailAddress, NotificationType notificationType) {
        String prefix = getPrefixForNotificationType(notificationType);
        return Optional.ofNullable(
                redisConnectionService.getValue(
                        prefix + HashHelper.hashSha256String(emailAddress)));
    }

    public void deleteOtpCode(String emailAddress, NotificationType notificationType) {
        String prefix = getPrefixForNotificationType(notificationType);
        long numberOfKeysRemoved =
                redisConnectionService.deleteValue(
                        prefix + HashHelper.hashSha256String(emailAddress));

        if (numberOfKeysRemoved == 0) {
            LOGGER.info(format("No %s key was deleted for: %s", prefix, emailAddress));
        }
    }

    public void saveAuthorizationCode(
            String authorizationCode, String clientSessionId, long codeExpiryTime) {
        try {
            redisConnectionService.saveWithExpiry(
                    authorizationCode, clientSessionId, codeExpiryTime);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String getPrefixForNotificationType(NotificationType notificationType) {
        switch (notificationType) {
            case VERIFY_EMAIL:
                return EMAIL_KEY_PREFIX;
            case VERIFY_PHONE_NUMBER:
                return PHONE_NUMBER_KEY_PREFIX;
            case MFA_SMS:
                return MFA_KEY_PREFIX;
            case RESET_PASSWORD:
                return RESET_PASSWORD_KEY_PREFIX;
        }
        throw new RuntimeException(
                String.format("No redis prefix key configured for %s", notificationType));
    }
}
