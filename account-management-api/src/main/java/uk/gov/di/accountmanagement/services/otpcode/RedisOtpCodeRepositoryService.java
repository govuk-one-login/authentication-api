package uk.gov.di.accountmanagement.services.otpcode;

import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.authentication.shared.services.RedisConnectionService;

public class RedisOtpCodeRepositoryService implements OtpCodeRepositoryService {

    private final RedisConnectionService redisConnectionService;

    public RedisOtpCodeRepositoryService(RedisConnectionService redisConnectionService) {
        this.redisConnectionService = redisConnectionService;
    }

    @Override
    public void saveOtpCode(String emailAddress, String code, long codeExpiryTime, NotificationType notificationType) {

    }

    @Override
    public void deleteOtpCode(String emailAddress, NotificationType notificationType) {

    }

    @Override
    public boolean isValidOtpCode(String emailAddress, String code, NotificationType notificationType) {
        return false;
    }
}
