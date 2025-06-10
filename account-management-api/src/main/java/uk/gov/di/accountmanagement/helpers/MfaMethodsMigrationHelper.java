package uk.gov.di.accountmanagement.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaMigrationFailureReason;

import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;

public class MfaMethodsMigrationHelper {
    private MfaMethodsMigrationHelper() {}

    public static Optional<APIGatewayProxyResponseEvent> migrateMfaCredentialsForUserIfRequired(
            UserProfile userProfile,
            MFAMethodsService mfaMethodsService,
            Logger loggerForCallingHandler) {
        if (!userProfile.isMfaMethodsMigrated()) {
            Optional<MfaMigrationFailureReason> maybeMfaMigrationFailureReason =
                    mfaMethodsService.migrateMfaCredentialsForUser(userProfile.getEmail());

            if (maybeMfaMigrationFailureReason.isPresent()) {
                MfaMigrationFailureReason mfaMigrationFailureReason =
                        maybeMfaMigrationFailureReason.get();

                loggerForCallingHandler.warn(
                        "Failed to migrate user's MFA credentials due to {}",
                        mfaMigrationFailureReason);

                return switch (mfaMigrationFailureReason) {
                    case NO_USER_FOUND_FOR_EMAIL -> Optional.of(
                            generateApiGatewayProxyErrorResponse(404, ErrorResponse.ERROR_1056));
                    case UNEXPECTED_ERROR_RETRIEVING_METHODS -> Optional.of(
                            generateApiGatewayProxyErrorResponse(500, ErrorResponse.ERROR_1064));
                    case ALREADY_MIGRATED -> Optional.empty();
                };
            } else {
                loggerForCallingHandler.info("MFA Methods migrated for user");
            }
        }

        return Optional.empty();
    }
}
