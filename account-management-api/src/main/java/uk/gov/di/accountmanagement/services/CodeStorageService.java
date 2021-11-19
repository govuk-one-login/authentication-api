package uk.gov.di.accountmanagement.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.authentication.shared.helpers.HashHelper;
import uk.gov.di.authentication.shared.services.RedisConnectionService;

import static java.lang.String.format;

public class CodeStorageService {

    private static final Logger LOGGER = LogManager.getLogger(CodeStorageService.class);
    private final RedisConnectionService redisConnectionService;
    private static final String EMAIL_KEY_PREFIX = "email-code:";
    private static final String PHONE_NUMBER_KEY_PREFIX = "phone-number-code:";

    public CodeStorageService(RedisConnectionService redisConnectionService) {
        this.redisConnectionService = redisConnectionService;
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

    public void deleteOtpCode(String emailAddress, NotificationType notificationType) {
        String prefix = getPrefixForNotificationType(notificationType);
        long numberOfKeysRemoved =
                redisConnectionService.deleteValue(
                        prefix + HashHelper.hashSha256String(emailAddress));

        if (numberOfKeysRemoved == 0) {
            LOGGER.info(format("No %s key was deleted", prefix));
        }
    }

    public boolean isValidOtpCode(
            String emailAddress, String code, NotificationType notificationType) {
        String prefix = getPrefixForNotificationType(notificationType);
        String codeFromRedis =
                redisConnectionService.getValue(prefix + HashHelper.hashSha256String(emailAddress));
        if (code.equals(codeFromRedis)) {
            deleteOtpCode(emailAddress, notificationType);
            return true;
        }
        return false;
    }

    private String getPrefixForNotificationType(NotificationType notificationType) {
        switch (notificationType) {
            case VERIFY_EMAIL:
                return EMAIL_KEY_PREFIX;
            case VERIFY_PHONE_NUMBER:
                return PHONE_NUMBER_KEY_PREFIX;
        }
        throw new RuntimeException(
                String.format("No redis prefix key configured for %s", notificationType));
    }
}
