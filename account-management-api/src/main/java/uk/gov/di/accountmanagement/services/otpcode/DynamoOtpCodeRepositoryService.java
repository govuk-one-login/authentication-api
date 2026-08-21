package uk.gov.di.accountmanagement.services.otpcode;

import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;

public class DynamoOtpCodeRepositoryService implements OtpCodeRepositoryService {

    private final AuthenticationAttemptsService dynamoConnectionService;

    public DynamoOtpCodeRepositoryService(AuthenticationAttemptsService dynamoConnectionService) {
        this.dynamoConnectionService = dynamoConnectionService;
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
