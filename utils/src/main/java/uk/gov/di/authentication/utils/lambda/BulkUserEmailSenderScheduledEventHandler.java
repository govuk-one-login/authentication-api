package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
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
import uk.gov.di.authentication.shared.services.SystemService;
import uk.gov.di.authentication.utils.exceptions.UnrecognisedSendModeException;
import uk.gov.di.authentication.utils.services.bulkemailsender.BulkEmailSender;
import uk.gov.di.authentication.utils.services.bulkemailsender.InternationalNumbersForcedMfaResetBulkEmailSender;
import uk.gov.di.authentication.utils.services.bulkemailsender.TermsAndConditionsBulkEmailSender;
import uk.gov.service.notify.NotificationClient;

import java.util.List;
import java.util.Map;

public class BulkUserEmailSenderScheduledEventHandler
        implements RequestHandler<ScheduledEvent, Void> {

    private static final Logger LOG =
            LogManager.getLogger(BulkUserEmailSenderScheduledEventHandler.class);

    public static final String DELIVERY_RECEIPT_STATUS_TEMPORARY_FAILURE = "temporary-failure";

    private final BulkEmailUsersService bulkEmailUsersService;
    private final ConfigurationService configurationService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final BulkEmailSender bulkEmailSender;

    public BulkUserEmailSenderScheduledEventHandler(
            BulkEmailUsersService bulkEmailUsersService,
            ConfigurationService configurationService,
            CloudwatchMetricsService cloudwatchMetricsService,
            BulkEmailSender bulkEmailSender) {
        this.bulkEmailUsersService = bulkEmailUsersService;
        this.configurationService = configurationService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.bulkEmailSender = bulkEmailSender;
    }

    public BulkUserEmailSenderScheduledEventHandler(
            ConfigurationService configurationService,
            BulkEmailUsersService bulkEmailUsersService,
            CloudwatchMetricsService cloudwatchMetricsService,
            NotificationService notificationService,
            AuditService auditService,
            DynamoService dynamoService) {
        this(
                bulkEmailUsersService,
                configurationService,
                cloudwatchMetricsService,
                provideBulkEmailSender(
                        configurationService,
                        bulkEmailUsersService,
                        cloudwatchMetricsService,
                        notificationService,
                        auditService,
                        dynamoService));
    }

    public BulkUserEmailSenderScheduledEventHandler(ConfigurationService configurationService) {
        this(
                configurationService,
                new BulkEmailUsersService(configurationService),
                new CloudwatchMetricsService(configurationService),
                new NotificationService(
                        configurationService
                                .getNotifyApiUrl()
                                .map(
                                        url ->
                                                new NotificationClient(
                                                        configurationService.getNotifyApiKey(),
                                                        url))
                                .orElse(
                                        new NotificationClient(
                                                configurationService.getNotifyApiKey())),
                        configurationService),
                new AuditService(configurationService),
                new DynamoService(configurationService));
    }

    public BulkUserEmailSenderScheduledEventHandler() {
        this(ConfigurationService.getInstance());
        this.configurationService.setSystemService(new SystemService());
    }

    public String getBulkEmailSenderClassName() {
        return bulkEmailSender.getClass().getSimpleName();
    }

    static BulkEmailSender provideBulkEmailSender(
            ConfigurationService configurationService,
            BulkEmailUsersService bulkEmailUsersService,
            CloudwatchMetricsService cloudwatchMetricsService,
            NotificationService notificationService,
            AuditService auditService,
            DynamoService dynamoService) {
        String senderType = configurationService.getBulkUserEmailSenderType();
        return switch (senderType) {
            case "TERMS_AND_CONDITIONS" -> new TermsAndConditionsBulkEmailSender(
                    bulkEmailUsersService,
                    cloudwatchMetricsService,
                    configurationService,
                    notificationService,
                    auditService,
                    dynamoService);
            case "INTERNATIONAL_NUMBERS_FORCED_MFA_RESET" -> new InternationalNumbersForcedMfaResetBulkEmailSender(
                    bulkEmailUsersService,
                    cloudwatchMetricsService,
                    configurationService,
                    notificationService,
                    auditService,
                    dynamoService);
            default -> throw new IllegalArgumentException(
                    "Unknown bulk email sender type: " + senderType);
        };
    }

    @Override
    public Void handleRequest(ScheduledEvent event, Context context) {

        LOG.info("Bulk User Email Send has been triggered.");
        final int bulkUserEmailBatchQueryLimit =
                configurationService.getBulkUserEmailBatchQueryLimit();
        final int bulkUserEmailMaxBatchCount = configurationService.getBulkUserEmailMaxBatchCount();
        final long bulkUserEmailBatchPauseDuration =
                configurationService.getBulkUserEmailBatchPauseDuration();
        final BulkEmailUserSendMode bulkEmailUserSendMode =
                readBulkEmailUserSendModeConfiguration(
                        configurationService.getBulkEmailUserSendMode());

        LOG.info(
                "Bulk User Email Send configuration - bulkUserEmailBatchQueryLimit: {}, bulkUserEmailMaxBatchCount: {}, bulkUserEmailBatchPauseDuration: {}, bulkEmailUserSendMode: {}",
                bulkUserEmailBatchQueryLimit,
                bulkUserEmailMaxBatchCount,
                bulkUserEmailBatchPauseDuration,
                bulkEmailUserSendMode);

        bulkEmailSender.validateConfiguration();

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
                    subjectId ->
                            bulkEmailSender.validateAndSendMessage(
                                    subjectId, bulkEmailUserSendMode));

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

    private void updateTableSizeMetric() {
        var noOfBulkEmailUserItems = bulkEmailUsersService.describeTable().table().itemCount();
        cloudwatchMetricsService.putEmbeddedValue(
                "NumberOfBulkEmailUsers", noOfBulkEmailUserItems, Map.of());
        LOG.info("BulkEmailUsers table item count: {}", noOfBulkEmailUserItems);
    }

    BulkEmailUserSendMode readBulkEmailUserSendModeConfiguration(String bulkEmailUserSendMode) {
        try {
            return BulkEmailUserSendMode.valueOf(bulkEmailUserSendMode);
        } catch (IllegalArgumentException e) {
            throw new UnrecognisedSendModeException(bulkEmailUserSendMode);
        }
    }
}
