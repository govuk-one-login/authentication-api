package uk.gov.di.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.helpers.HashHelper;

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

    public CodeStorageService(RedisConnectionService redisConnectionService) {
        this.redisConnectionService = redisConnectionService;
    }

    public void saveEmailCode(String email, String code, long codeExpiryTime) {
        String encodedhash = HashHelper.hashSha256String(email);
        String key = EMAIL_KEY_PREFIX + encodedhash;
        try {
            redisConnectionService.saveWithExpiry(key, code, codeExpiryTime);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
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

    public void saveMfaCode(String emailAddress, String code, long codeExpiryTime) {
        String hashedEmailAddress = HashHelper.hashSha256String(emailAddress);
        String key = MFA_KEY_PREFIX + hashedEmailAddress;
        try {
            redisConnectionService.saveWithExpiry(key, code, codeExpiryTime);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void savePhoneNumberCode(String emailAddress, String code, long codeExpiryTime) {
        String hashedEmailAddress = HashHelper.hashSha256String(emailAddress);
        String key = PHONE_NUMBER_KEY_PREFIX + hashedEmailAddress;
        try {
            redisConnectionService.saveWithExpiry(key, code, codeExpiryTime);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public boolean isCodeBlockedForSession(String emailAddress, String sessionId) {
        return redisConnectionService.getValue(
                        CODE_BLOCKED_KEY_PREFIX
                                + HashHelper.hashSha256String(emailAddress)
                                + sessionId)
                != null;
    }

    public Optional<String> getPhoneNumberCode(String emailAddress) {
        return Optional.ofNullable(
                redisConnectionService.getValue(
                        PHONE_NUMBER_KEY_PREFIX + HashHelper.hashSha256String(emailAddress)));
    }

    public Optional<String> getEmailCode(String emailAddress) {
        return Optional.ofNullable(
                redisConnectionService.getValue(
                        EMAIL_KEY_PREFIX + HashHelper.hashSha256String(emailAddress)));
    }

    public void deleteEmailCode(String emailAddress) {
        long numberOfKeysRemoved =
                redisConnectionService.deleteValue(
                        EMAIL_KEY_PREFIX + HashHelper.hashSha256String(emailAddress));

        if (numberOfKeysRemoved == 0) {
            LOGGER.info(format("No %s key was deleted for: %s", EMAIL_KEY_PREFIX, emailAddress));
        }
    }

    public void deletePhoneNumberCode(String emailAddress) {
        long numberOfKeysRemoved =
                redisConnectionService.deleteValue(
                        PHONE_NUMBER_KEY_PREFIX + HashHelper.hashSha256String(emailAddress));

        if (numberOfKeysRemoved == 0) {
            LOGGER.info(
                    format("No %s key was deleted for: %s", PHONE_NUMBER_KEY_PREFIX, emailAddress));
        }
    }
}
