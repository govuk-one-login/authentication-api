package uk.gov.di.authentication.utils.services.bulkemailsender;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.entity.BulkEmailUserSendMode;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.NotificationService;
import uk.gov.di.authentication.utils.domain.BulkEmailType;
import uk.gov.di.authentication.utils.domain.UtilsAuditableEvent;
import uk.gov.di.authentication.utils.exceptions.IncludedTermsAndConditionsConfigMissingException;
import uk.gov.service.notify.NotificationClientException;

import java.util.List;
import java.util.Map;

import static uk.gov.di.audit.AuditContext.emptyAuditContext;
import static uk.gov.di.authentication.shared.entity.NotificationType.TERMS_AND_CONDITIONS_BULK_EMAIL;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class TermsAndConditionsBulkEmailSender extends BaseBulkEmailSender {

    private static final Logger LOG = LogManager.getLogger(TermsAndConditionsBulkEmailSender.class);

    private final List<String> includedTermsAndConditions;
    private final NotificationService notificationService;
    private final AuditService auditService;
    private final DynamoService dynamoService;

    public TermsAndConditionsBulkEmailSender(
            BulkEmailUsersService bulkEmailUsersService,
            CloudwatchMetricsService cloudwatchMetricsService,
            ConfigurationService configurationService,
            NotificationService notificationService,
            AuditService auditService,
            DynamoService dynamoService) {
        super(bulkEmailUsersService, cloudwatchMetricsService, configurationService);
        this.includedTermsAndConditions =
                configurationService.getBulkUserEmailIncludedTermsAndConditions();
        this.notificationService = notificationService;
        this.auditService = auditService;
        this.dynamoService = dynamoService;
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
        var auditableEvent =
                BulkEmailUserSendMode.DELIVERY_RECEIPT_TEMPORARY_FAILURE_RETRIES.equals(sendMode)
                        ? UtilsAuditableEvent.AUTH_BULK_RETRY_EMAIL_SENT
                        : UtilsAuditableEvent.AUTH_BULK_EMAIL_SENT;

        try {
            var emailSent = false;
            if (configurationService.isBulkUserEmailEmailSendingEnabled()) {
                LOG.info("Bulk user email sending email.");
                notificationService.sendEmail(
                        userProfile.getEmail(), Map.of(), TERMS_AND_CONDITIONS_BULK_EMAIL, "");
                emailSent = true;
            } else {
                LOG.info("Bulk user email email sending not enabled.");
            }

            if (emailSent) {
                var internalCommonSubjectIdentifier =
                        userProfile.getSalt() != null
                                ? ClientSubjectHelper.getSubjectWithSectorIdentifier(
                                                userProfile,
                                                configurationService.getInternalSectorUri(),
                                                dynamoService)
                                        .getValue()
                                : AuditService.UNKNOWN;
                auditService.submitAuditEvent(
                        auditableEvent,
                        emptyAuditContext()
                                .withEmail(userProfile.getEmail())
                                .withSubjectId(internalCommonSubjectIdentifier),
                        pair("internalSubjectId", userProfile.getSubjectID()),
                        pair("bulk-email-type", BulkEmailType.VC_EXPIRY_BULK_EMAIL.name()));
            }
            updateBulkUserStatus(subjectId, successStatus);
        } catch (NotificationClientException e) {
            LOG.error("Unable to send bulk email to user: {}", e.getMessage());
            updateBulkUserStatus(subjectId, BulkEmailStatus.ERROR_SENDING_EMAIL);
        }
    }
}
