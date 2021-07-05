package uk.gov.di.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.helpers.HashHelper;

import java.util.Optional;

public class CodeStorageService {

    private static final Logger LOGGER = LoggerFactory.getLogger(CodeStorageService.class);

    private final RedisConnectionService redisConnectionService;
    private static final String EMAIL_KEY_PREFIX = "email-code:";
    private static final String PHONE_NUMBER_KEY_PREFIX = "phone-number-code:";

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

    public void savePhoneNumberCode(String emailAddress, String code, long codeExpiryTime) {
        String hashedEmailAddress = HashHelper.hashSha256String(emailAddress);
        String key = PHONE_NUMBER_KEY_PREFIX + hashedEmailAddress;
        try {
            redisConnectionService.saveWithExpiry(key, code, codeExpiryTime);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Optional<String> getCodeForEmail(String emailAddress) {
        return Optional.ofNullable(
                redisConnectionService.getValue(
                        EMAIL_KEY_PREFIX + HashHelper.hashSha256String(emailAddress)));
    }

    public void deleteCodeForEmail(String emailAddress) {
        long numberOfKeysRemoved =
                redisConnectionService.deleteValue(
                        EMAIL_KEY_PREFIX + HashHelper.hashSha256String(emailAddress));

        if (numberOfKeysRemoved == 0) {
            LOGGER.info("No key was deleted for: " + emailAddress);
        }
    }
}
