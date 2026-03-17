package uk.gov.di.authentication.utils.services.bulkemailsender;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.entity.BulkEmailUserSendMode;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.PhoneNumberHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.NotificationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.utils.domain.BulkEmailType;
import uk.gov.service.notify.NotificationClientException;

import static uk.gov.di.authentication.shared.conditions.MfaHelper.hasInternationalPhoneNumber;
import static uk.gov.di.authentication.shared.entity.NotificationType.INTERNATIONAL_NUMBERS_FORCED_MFA_RESET_BULK_EMAIL;

public class InternationalNumbersForcedMfaResetBulkEmailSender extends BaseBulkEmailSender {

    private static final Logger LOG =
            LogManager.getLogger(InternationalNumbersForcedMfaResetBulkEmailSender.class);

    private final MFAMethodsService mfaMethodsService;

    public InternationalNumbersForcedMfaResetBulkEmailSender(
            BulkEmailUsersService bulkEmailUsersService,
            CloudwatchMetricsService cloudwatchMetricsService,
            ConfigurationService configurationService,
            NotificationService notificationService,
            AuditService auditService,
            DynamoService dynamoService,
            MFAMethodsService mfaMethodsService) {
        super(
                bulkEmailUsersService,
                cloudwatchMetricsService,
                configurationService,
                auditService,
                dynamoService,
                notificationService);
        this.mfaMethodsService = mfaMethodsService;
    }

    @Override
    public void validateConfiguration() {
        // No-op method as this sender has no configuration that needs validating
    }

    @Override
    public void validateAndSendMessage(String subjectId, BulkEmailUserSendMode sendMode) {
        var userProfileOptional = dynamoService.getOptionalUserProfileFromSubject(subjectId);
        if (userProfileOptional.isEmpty()) {
            LOG.warn("User not found by subject id");
            updateBulkUserStatus(subjectId, BulkEmailStatus.ACCOUNT_NOT_FOUND);
            return;
        }
        var userProfile = userProfileOptional.get();

        if (!hasInternationalNumber(userProfile)) {
            LOG.info("User does not have international phone number");
            updateBulkUserStatus(subjectId, BulkEmailStatus.NO_INTERNATIONAL_NUMBER);
            return;
        }

        var successStatus = sendMode.mapToSuccessStatus();

        try {
            var emailSent =
                    sendEmail(userProfile, INTERNATIONAL_NUMBERS_FORCED_MFA_RESET_BULK_EMAIL);

            if (emailSent) {
                submitAuditEvent(
                        userProfile,
                        sendMode,
                        BulkEmailType.INTERNATIONAL_NUMBERS_FORCED_MFA_RESET_BULK_EMAIL);
            }
            updateBulkUserStatus(subjectId, successStatus);
        } catch (NotificationClientException e) {
            LOG.error("Unable to send bulk email to user: {}", e.getMessage());
            updateBulkUserStatus(subjectId, BulkEmailStatus.ERROR_SENDING_EMAIL);
        }
    }

    /**
     * Here we return true if the user has an international number as an MFA method. Rather than
     * using the MfaMethodService to do most of the data fetch we check the UserProfile first in
     * order to save on a fetch of the UserCredentials if we don't have to (i.e. the user has an
     * international number in their UserProfile, or they have not done the MfaMethodsMigration to
     * UserCredentials)
     */
    private boolean hasInternationalNumber(UserProfile userProfile) {
        var phoneNumber = userProfile.getPhoneNumber();
        if (phoneNumber != null && !PhoneNumberHelper.isDomesticPhoneNumber(phoneNumber)) {
            return true;
        }
        if (!userProfile.isMfaMethodsMigrated()) {
            return false;
        }
        var userCredentials = dynamoService.getUserCredentialsFromEmail(userProfile.getEmail());
        if (userCredentials == null) {
            return false;
        }
        var mfaMethodsResult = mfaMethodsService.getMfaMethods(userProfile, userCredentials, true);
        return mfaMethodsResult.isSuccess()
                && hasInternationalPhoneNumber(mfaMethodsResult.getSuccess());
    }
}
