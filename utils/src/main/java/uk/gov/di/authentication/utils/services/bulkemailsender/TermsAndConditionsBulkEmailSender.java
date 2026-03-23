package uk.gov.di.authentication.utils.services.bulkemailsender;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.entity.BulkEmailUserSendMode;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.NotificationService;
import uk.gov.di.authentication.utils.domain.BulkEmailType;
import uk.gov.di.authentication.utils.exceptions.IncludedTermsAndConditionsConfigMissingException;
import uk.gov.service.notify.NotificationClientException;

import java.util.List;

import static uk.gov.di.authentication.shared.entity.NotificationType.TERMS_AND_CONDITIONS_BULK_EMAIL;

public class TermsAndConditionsBulkEmailSender extends BaseBulkEmailSender {

    private static final Logger LOG = LogManager.getLogger(TermsAndConditionsBulkEmailSender.class);

    private final List<String> includedTermsAndConditions;

    public TermsAndConditionsBulkEmailSender(
            BulkEmailUsersService bulkEmailUsersService,
            CloudwatchMetricsService cloudwatchMetricsService,
            ConfigurationService configurationService,
            NotificationService notificationService,
            AuditService auditService,
            DynamoService dynamoService) {
        super(
                bulkEmailUsersService,
                cloudwatchMetricsService,
                configurationService,
                auditService,
                dynamoService,
                notificationService);
        this.includedTermsAndConditions =
                configurationService.getBulkUserEmailIncludedTermsAndConditions();
    }

    @Override
    public void validateConfiguration() {
        if (includedTermsAndConditions.isEmpty()) {
            throw new IncludedTermsAndConditionsConfigMissingException();
        }
        LOG.info(
                "TermsAndConditionsBulkEmailSender configuration - includedTermsAndConditions: {}",
                includedTermsAndConditions);
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

        var hasAcceptedRecentTermsAndConditions =
                userProfile.getTermsAndConditions() != null
                        && !includedTermsAndConditions.contains(
                                userProfile.getTermsAndConditions().getVersion());

        if (hasAcceptedRecentTermsAndConditions) {
            updateBulkUserStatus(subjectId, BulkEmailStatus.TERMS_ACCEPTED_RECENTLY);
            return;
        }

        var successStatus = sendMode.mapToSuccessStatus();

        try {
            var emailSent = sendEmail(userProfile, TERMS_AND_CONDITIONS_BULK_EMAIL);

            if (emailSent) {
                submitAuditEvent(userProfile, sendMode, BulkEmailType.VC_EXPIRY_BULK_EMAIL);
            }
            updateBulkUserStatus(subjectId, successStatus);
        } catch (NotificationClientException e) {
            LOG.error("Unable to send bulk email to user: {}", e.getMessage());
            updateBulkUserStatus(subjectId, BulkEmailStatus.ERROR_SENDING_EMAIL);
        }
    }
}
