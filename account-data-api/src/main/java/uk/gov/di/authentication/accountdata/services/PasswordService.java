package uk.gov.di.authentication.accountdata.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.accountdata.entity.password.failurereasons.VerifyPasswordFailureReason;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.util.Optional;

public class PasswordService {

    private static final Logger LOG = LogManager.getLogger(PasswordService.class);

    private final ConfigurationService configurationService;
    private final DynamoService dynamoService;

    public PasswordService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dynamoService = new DynamoService(configurationService);
    }

    public PasswordService(ConfigurationService configurationService, DynamoService dynamoService) {
        this.configurationService = configurationService;
        this.dynamoService = dynamoService;
    }

    public Result<VerifyPasswordFailureReason, Boolean> verifyPassword(
            String publicSubjectId, String password) {
        Optional<UserProfile> maybeUserProfile =
                dynamoService.getOptionalUserProfileFromPublicSubject(publicSubjectId);

        if (maybeUserProfile.isEmpty()) {
            LOG.warn("UserProfile not found for public subject ID {}", publicSubjectId);
            return Result.failure(VerifyPasswordFailureReason.USER_NOT_FOUND);
        }
        var userProfile = maybeUserProfile.get();

        var isPasswordValid = dynamoService.login(userProfile.getEmail(), password);
        return Result.success(isPasswordValid);
    }
}
