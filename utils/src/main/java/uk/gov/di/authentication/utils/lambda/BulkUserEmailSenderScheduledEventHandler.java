package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.helpers.LocaleHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.NotificationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.service.notify.NotificationClient;
import uk.gov.service.notify.NotificationClientException;

import java.util.List;
import java.util.Map;

import static uk.gov.di.authentication.shared.entity.NotificationType.TERMS_AND_CONDITIONS_BULK_EMAIL;

public class BulkUserEmailSenderScheduledEventHandler
        implements RequestHandler<ScheduledEvent, Void> {

    private static final Logger LOG =
            LogManager.getLogger(BulkUserEmailSenderScheduledEventHandler.class);

    private final BulkEmailUsersService bulkEmailUsersService;

    private final DynamoService dynamoService;

    private final NotificationService notificationService;

    private final ConfigurationService configurationService;

    protected final Json objectMapper = SerializationService.getInstance();

    public BulkUserEmailSenderScheduledEventHandler() {
        this(ConfigurationService.getInstance());
    }

    public BulkUserEmailSenderScheduledEventHandler(
            BulkEmailUsersService bulkEmailUsersService,
            DynamoService dynamoService,
            ConfigurationService configurationService,
            NotificationService notificationService) {
        this.bulkEmailUsersService = bulkEmailUsersService;
        this.dynamoService = dynamoService;
        this.configurationService = configurationService;
        this.notificationService = notificationService;
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
    }

    @Override
    public Void handleRequest(ScheduledEvent event, Context context) {

        LOG.info("Bulk User Email Send has been triggered.");
        final int bulkUserEmailBatchQueryLimit =
                configurationService.getBulkUserEmailBatchQueryLimit();
        final int bulkUserEmailMaxBatchCount = configurationService.getBulkUserEmailMaxBatchCount();
        final long bulkUserEmailBatchPauseDuration =
                configurationService.getBulkUserEmailBatchPauseDuration();
        List<String> userSubjectIdBatch;

        int batchCounter = 0;
        do {
            batchCounter++;
            userSubjectIdBatch =
                    bulkEmailUsersService.getNSubjectIdsByStatus(
                            bulkUserEmailBatchQueryLimit, BulkEmailStatus.PENDING);

            LOG.info(
                    "Retrieved user subject ids for batch no: {} no of users: {}",
                    batchCounter,
                    userSubjectIdBatch.size());

            userSubjectIdBatch.forEach(
                    subjectId -> {
                        dynamoService
                                .getOptionalUserProfileFromSubject(subjectId)
                                .ifPresentOrElse(
                                        userProfile -> {
                                            try {
                                                sendNotifyEmail(userProfile.getEmail());
                                                updateBulkUserStatus(
                                                        subjectId, BulkEmailStatus.EMAIL_SENT);
                                            } catch (NotificationClientException e) {
                                                LOG.error(
                                                        "Unable to send bulk email to user: {}",
                                                        e.getMessage());
                                                updateBulkUserStatus(
                                                        subjectId,
                                                        BulkEmailStatus.ERROR_SENDING_EMAIL);
                                            }
                                        },
                                        () -> {
                                            LOG.warn("User not found by subject id");
                                            updateBulkUserStatus(
                                                    subjectId, BulkEmailStatus.ACCOUNT_NOT_FOUND);
                                        });
                    });

            try {
                if (bulkUserEmailBatchPauseDuration > 0) {
                    LOG.info(
                            "Bulk user email batch pausing for: {}ms",
                            bulkUserEmailBatchPauseDuration);
                    Thread.sleep(bulkUserEmailBatchPauseDuration);
                    LOG.info("Bulk user email batch pause complete.");
                }
            } catch (InterruptedException e) {
                LOG.warn("Thread sleep for bulk user email batch pause interrupted.");
            }
        } while (!userSubjectIdBatch.isEmpty() && batchCounter < bulkUserEmailMaxBatchCount);

        return null;
    }

    private void sendNotifyEmail(String email) throws NotificationClientException {
        notificationService.sendEmail(
                email,
                Map.of(),
                TERMS_AND_CONDITIONS_BULK_EMAIL,
                LocaleHelper.SupportedLanguage.EN);
    }

    private void updateBulkUserStatus(String subjectId, BulkEmailStatus bulkEmailStatus) {
        if (bulkEmailUsersService.updateUserStatus(subjectId, bulkEmailStatus).isPresent()) {
            LOG.info("Bulk email user status updated to: {}", bulkEmailStatus.getValue());
        } else {
            LOG.warn("Bulk user email status not updated, user not found.");
        }
    }
}
