package uk.gov.di.accountmanagement.services.otpcode;

import uk.gov.di.accountmanagement.entity.NotificationType;

public interface OtpCodeRepositoryService {
    void saveOtpCode(
            String emailAddress,
            String code,
            long codeExpiryTime,
            NotificationType notificationType);

    void deleteOtpCode(String emailAddress, NotificationType notificationType);

    boolean isValidOtpCode(String emailAddress, String code, NotificationType notificationType);
}
