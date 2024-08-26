package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.entity.BulkEmailUserSendMode;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.NotificationService;
import uk.gov.di.authentication.shared.services.SystemService;
import uk.gov.di.authentication.utils.domain.BulkEmailType;
import uk.gov.di.authentication.utils.domain.UtilsAuditableEvent;
import uk.gov.di.authentication.utils.exceptions.IncludedTermsAndConditionsConfigMissingException;
import uk.gov.di.authentication.utils.exceptions.UnrecognisedSendModeException;
import uk.gov.service.notify.NotificationClient;
import uk.gov.service.notify.NotificationClientException;

import java.util.List;
import java.util.Map;

import static uk.gov.di.audit.AuditContext.emptyAuditContext;
import static uk.gov.di.authentication.shared.entity.NotificationType.TERMS_AND_CONDITIONS_BULK_EMAIL;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class BulkUserEmailSenderScheduledEventHandler
        implements RequestHandler<ScheduledEvent, Void> {

    private static final Logger LOG =
            LogManager.getLogger(BulkUserEmailSenderScheduledEventHandler.class);

    public static final String DELIVERY_RECEIPT_STATUS_TEMPORARY_FAILURE = "temporary-failure";

    private final BulkEmailUsersService bulkEmailUsersService;

    private final DynamoService dynamoService;

    private final NotificationService notificationService;

    private final ConfigurationService configurationService;

    private final CloudwatchMetricsService cloudwatchMetricsService;

    private final AuditService auditService;

    public BulkUserEmailSenderScheduledEventHandler() {
        this(ConfigurationService.getInstance());
        this.configurationService.setSystemService(new SystemService());
    }

    public BulkUserEmailSenderScheduledEventHandler(
            BulkEmailUsersService bulkEmailUsersService,
            DynamoService dynamoService,
            ConfigurationService configurationService,
            NotificationService notificationService,
            CloudwatchMetricsService cloudwatchMetricsService,
            AuditService auditService) {
        this.bulkEmailUsersService = bulkEmailUsersService;
        this.dynamoService = dynamoService;
        this.configurationService = configurationService;
        this.notificationService = notificationService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.auditService = auditService;
    }

    public BulkUserEmailSenderScheduledEventHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.bulkEmailUsersService = new BulkEmailUsersService(configurationService);
        this.dynamoService = new DynamoService(configurationService);
        NotificationClient client =
                configurationService
                        .getNotifyApiUrl()
                        .map(
                                url ->
                                        new NotificationClient(
                                                configurationService.getNotifyApiKey(), url))
                        .orElse(new NotificationClient(configurationService.getNotifyApiKey()));
        this.notificationService = new NotificationService(client, configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
        this.auditService = new AuditService(configurationService);
    }

    @Override
    public Void handleRequest(ScheduledEvent event, Context context) {

        LOG.info("Bulk User Email Send has been triggered.");
        final int bulkUserEmailBatchQueryLimit =
                configurationService.getBulkUserEmailBatchQueryLimit();
        final int bulkUserEmailMaxBatchCount = configurationService.getBulkUserEmailMaxBatchCount();
        final long bulkUserEmailBatchPauseDuration =
                configurationService.getBulkUserEmailBatchPauseDuration();
        final List<String> bulkUserEmailIncludedTermsAndConditions =
                configurationService.getBulkUserEmailIncludedTermsAndConditions();
        final BulkEmailUserSendMode bulkEmailUserSendMode =
                readBulkEmailUserSendModeConfiguration(
                        configurationService.getBulkEmailUserSendMode());
        final BulkEmailStatus successStatus = bulkEmailUserSendMode.mapToSuccessStatus();
        final UtilsAuditableEvent auditableEvent =
                BulkEmailUserSendMode.DELIVERY_RECEIPT_TEMPORARY_FAILURE_RETRIES.equals(
                                bulkEmailUserSendMode)
                        ? UtilsAuditableEvent.AUTH_BULK_RETRY_EMAIL_SENT
                        : UtilsAuditableEvent.AUTH_BULK_EMAIL_SENT;

        if (bulkUserEmailIncludedTermsAndConditions.isEmpty()) {
            throw new IncludedTermsAndConditionsConfigMissingException();
        }

        LOG.info(
                "Bulk User Email Send configuration - bulkUserEmailBatchQueryLimit: {}, bulkUserEmailMaxBatchCount: {}, bulkUserEmailBatchPauseDuration: {}, includedTermsAndConditions: {}, bulkEmailUserSendMode: {}",
                bulkUserEmailBatchQueryLimit,
                bulkUserEmailMaxBatchCount,
                bulkUserEmailBatchPauseDuration,
                bulkUserEmailIncludedTermsAndConditions,
                bulkEmailUserSendMode);

        updateTableSizeMetric();

        List<String> userSubjectIdBatch;

        int batchCounter = 0;
        do {
            batchCounter++;
            userSubjectIdBatch =
                    getUserIdSubjectBatch(bulkEmailUserSendMode, bulkUserEmailBatchQueryLimit);

            LOG.info(
                    "Retrieved user subject ids for batch no: {} no of users: {}",
                    batchCounter,
                    userSubjectIdBatch.size());

            userSubjectIdBatch.forEach(
                    subjectId -> {
                        dynamoService
                                .getOptionalUserProfileFromSubject(subjectId)
                                .ifPresentOrElse(
                                        userProfile ->
                                                sendEmailIfRequiredAndUpdateStatus(
                                                        userProfile,
                                                        subjectId,
                                                        bulkUserEmailIncludedTermsAndConditions,
                                                        successStatus,
                                                        auditableEvent),
                                        () -> {
                                            LOG.warn("User not found by subject id");
                                            updateBulkUserStatus(
                                                    subjectId, BulkEmailStatus.ACCOUNT_NOT_FOUND);
                                        });
                    });

            try {
                if (bulkUserEmailBatchPauseDuration > 0) {
                    LOG.info(
                            "Bulk user email batch pausing for: {} ms",
                            bulkUserEmailBatchPauseDuration);
                    Thread.sleep(bulkUserEmailBatchPauseDuration);
                    LOG.info("Bulk user email batch pause complete.");
                }
            } catch (InterruptedException e) {
                LOG.warn("Thread sleep for bulk user email batch pause interrupted.");
                Thread.currentThread().interrupt();
            }
        } while (!userSubjectIdBatch.isEmpty() && batchCounter < bulkUserEmailMaxBatchCount);

        LOG.info("Bulk user email: batch completed.");
        return null;
    }

    private List<String> getUserIdSubjectBatch(BulkEmailUserSendMode sendMode, Integer limit) {
        switch (sendMode) {
            case PENDING:
                return bulkEmailUsersService.getNSubjectIdsByStatus(limit, BulkEmailStatus.PENDING);
            case NOTIFY_ERROR_RETRIES:
                return bulkEmailUsersService.getNSubjectIdsByStatus(
                        limit, BulkEmailStatus.ERROR_SENDING_EMAIL);
            case DELIVERY_RECEIPT_TEMPORARY_FAILURE_RETRIES:
                return bulkEmailUsersService.getNSubjectIdsByDeliveryReceiptStatus(
                        limit, DELIVERY_RECEIPT_STATUS_TEMPORARY_FAILURE);
            default:
                throw new UnrecognisedSendModeException(sendMode.getValue());
        }
    }

    private boolean sendNotifyEmail(String email) throws NotificationClientException {
        if (configurationService.isBulkUserEmailEmailSendingEnabled()) {
            LOG.info("Bulk user email sending email.");
            notificationService.sendEmail(email, Map.of(), TERMS_AND_CONDITIONS_BULK_EMAIL);
            return true;
        } else {
            LOG.info("Bulk user email email sending not enabled.");
            return false;
        }
    }

    private void sendEmailIfRequiredAndUpdateStatus(
            UserProfile userProfile,
            String subjectId,
            List<String> bulkUserEmailIncludedTermsAndConditions,
            BulkEmailStatus successStatus,
            UtilsAuditableEvent utilsAuditableEvent) {
        boolean hasAcceptedRecentTermsAndConditions =
                (userProfile.getTermsAndConditions() != null
                        && !bulkUserEmailIncludedTermsAndConditions.contains(
                                userProfile.getTermsAndConditions().getVersion()));
        if (hasAcceptedRecentTermsAndConditions) {
            updateBulkUserStatus(subjectId, BulkEmailStatus.TERMS_ACCEPTED_RECENTLY);
        } else {
            try {
                if (sendNotifyEmail(userProfile.getEmail())) {
                    addAuditEventForEmailSent(userProfile, utilsAuditableEvent);
                }
                updateBulkUserStatus(subjectId, successStatus);
            } catch (NotificationClientException e) {
                LOG.error("Unable to send bulk email to user: {}", e.getMessage());
                updateBulkUserStatus(subjectId, BulkEmailStatus.ERROR_SENDING_EMAIL);
            }
        }
    }

    private void updateBulkUserStatus(String subjectId, BulkEmailStatus bulkEmailStatus) {
        if (bulkEmailUsersService.updateUserStatus(subjectId, bulkEmailStatus).isPresent()) {
            LOG.info("Bulk email user status updated to: {}", bulkEmailStatus.getValue());
        } else {
            LOG.warn("Bulk user email status not updated, user not found.");
        }
        updateBulkUserStatusMetric(bulkEmailStatus);
    }

    private void updateTableSizeMetric() {
        var noOfBulkEmailUserItems = bulkEmailUsersService.describeTable().table().itemCount();
        cloudwatchMetricsService.putEmbeddedValue(
                "NumberOfBulkEmailUsers", noOfBulkEmailUserItems, Map.of());
        LOG.info("BulkEmailUsers table item count: {}", noOfBulkEmailUserItems);
    }

    private void updateBulkUserStatusMetric(BulkEmailStatus bulkEmailStatus) {
        cloudwatchMetricsService.incrementCounter(
                "BulkEmailStatus",
                Map.of(
                        "Status",
                        bulkEmailStatus.getValue(),
                        "Environment",
                        configurationService.getEnvironment()));
    }

    private void addAuditEventForEmailSent(
            UserProfile userProfile, UtilsAuditableEvent utilsAuditableEvent) {
        var internalCommonSubjectIdentifier =
                userProfile.getSalt() != null
                        ? ClientSubjectHelper.getSubjectWithSectorIdentifier(
                                        userProfile,
                                        configurationService.getInternalSectorUri(),
                                        dynamoService)
                                .getValue()
                        : AuditService.UNKNOWN;
        auditService.submitAuditEvent(
                utilsAuditableEvent,
                emptyAuditContext()
                        .withEmail(userProfile.getEmail())
                        .withSubjectId(internalCommonSubjectIdentifier),
                pair("internalSubjectId", userProfile.getSubjectID()),
                pair("bulk-email-type", BulkEmailType.VC_EXPIRY_BULK_EMAIL.name()));
    }

    BulkEmailUserSendMode readBulkEmailUserSendModeConfiguration(String bulkEmailUserSendMode) {
        try {
            return BulkEmailUserSendMode.valueOf(bulkEmailUserSendMode);
        } catch (IllegalArgumentException e) {
            throw new UnrecognisedSendModeException(bulkEmailUserSendMode);
        }
    }
}
