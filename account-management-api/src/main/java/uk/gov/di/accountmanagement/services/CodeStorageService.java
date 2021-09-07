package uk.gov.di.accountmanagement.services;

import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.authentication.shared.helpers.HashHelper;
import uk.gov.di.authentication.shared.services.RedisConnectionService;

public class CodeStorageService {

    private final RedisConnectionService redisConnectionService;
    private static final String EMAIL_KEY_PREFIX = "email-code:";

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

    private String getPrefixForNotificationType(NotificationType notificationType) {
        switch (notificationType) {
            case VERIFY_EMAIL:
                return EMAIL_KEY_PREFIX;
        }
        throw new RuntimeException(
                String.format("No redis prefix key configured for %s", notificationType));
    }
}
