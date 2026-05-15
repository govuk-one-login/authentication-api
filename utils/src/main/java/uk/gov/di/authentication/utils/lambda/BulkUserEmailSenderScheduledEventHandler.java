package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.entity.BulkEmailUserSendMode;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.NotificationService;
import uk.gov.di.authentication.shared.services.SystemService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.utils.exceptions.UnrecognisedSendModeException;
import uk.gov.di.authentication.utils.services.bulkemailsender.BulkEmailSender;
import uk.gov.di.authentication.utils.services.bulkemailsender.InternationalNumbersForcedMfaResetBulkEmailSender;
import uk.gov.di.authentication.utils.services.bulkemailsender.TermsAndConditionsBulkEmailSender;
import uk.gov.service.notify.NotificationClient;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

public class BulkUserEmailSenderScheduledEventHandler
        implements RequestHandler<ScheduledEvent, Void> {

    private static final Logger LOG =
            LogManager.getLogger(BulkUserEmailSenderScheduledEventHandler.class);

    public static final String DELIVERY_RECEIPT_STATUS_TEMPORARY_FAILURE = "temporary-failure";
    private static final int PARALLELISM = 10;
    private static final int MAX_QUERY_PAGE_SIZE = 100;

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
            DynamoService dynamoService,
            MFAMethodsService maybeMfaMethodsService) {
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
                        dynamoService,
                        maybeMfaMethodsService));
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
                new DynamoService(configurationService),
                null);
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
            DynamoService dynamoService,
            MFAMethodsService maybeMfaMethodsService) {
        String senderType = configurationService.getBulkUserEmailSenderType();
        return switch (senderType) {
            case "TERMS_AND_CONDITIONS" ->
                    new TermsAndConditionsBulkEmailSender(
                            bulkEmailUsersService,
                            cloudwatchMetricsService,
                            configurationService,
                            notificationService,
                            auditService,
                            dynamoService);
            case "INTERNATIONAL_NUMBERS_FORCED_MFA_RESET" ->
                    new InternationalNumbersForcedMfaResetBulkEmailSender(
                            bulkEmailUsersService,
                            cloudwatchMetricsService,
                            configurationService,
                            notificationService,
                            auditService,
                            dynamoService,
                            maybeMfaMethodsService != null
                                    ? maybeMfaMethodsService
                                    : new MFAMethodsService(configurationService));
            default ->
                    throw new IllegalArgumentException(
                            "Unknown bulk email sender type: " + senderType);
        };
    }

    @Override
    public Void handleRequest(ScheduledEvent event, Context context) {

        LOG.info("Bulk User Email Send has been triggered.");
        final int bulkUserEmailBatchSize = configurationService.getBulkUserEmailBatchSize();
        final BulkEmailUserSendMode bulkEmailUserSendMode =
                readBulkEmailUserSendModeConfiguration(
                        configurationService.getBulkEmailUserSendMode());

        LOG.info(
                "Bulk User Email Send configuration - bulkUserEmailBatchSize: {}, bulkEmailUserSendMode: {}",
                bulkUserEmailBatchSize,
                bulkEmailUserSendMode);

        if (bulkUserEmailBatchSize <= 0) {
            LOG.info("Bulk user email batch size is 0, nothing to process.");
            return null;
        }

        bulkEmailSender.validateConfiguration();

        updateTableSizeMetric();

        List<String> allUserSubjectIds = new ArrayList<>();
        Map<String, AttributeValue> lastEvaluatedKey = null;
        int batchCounter = 0;
        boolean hasMoreResults = true;
        while (allUserSubjectIds.size() < bulkUserEmailBatchSize && hasMoreResults) {
            batchCounter++;
            int queryLimit =
                    Math.min(
                            MAX_QUERY_PAGE_SIZE, bulkUserEmailBatchSize - allUserSubjectIds.size());

            var result =
                    getUserIdSubjectBatchPaginated(
                            bulkEmailUserSendMode, queryLimit, lastEvaluatedKey);

            allUserSubjectIds.addAll(result.subjectIds());
            lastEvaluatedKey = result.lastEvaluatedKey();
            hasMoreResults = lastEvaluatedKey != null && !lastEvaluatedKey.isEmpty();

            LOG.info(
                    "Retrieved user subject ids for batch no: {} fetched: {} total: {}",
                    batchCounter,
                    result.subjectIds().size(),
                    allUserSubjectIds.size());
        }

        ExecutorService executor = Executors.newFixedThreadPool(PARALLELISM);
        TaskCounters counters = new TaskCounters();
        long startTime = System.currentTimeMillis();
        int taskTimeoutSeconds = configurationService.getBulkUserEmailTaskTimeoutSeconds();
        int stopNewRequestsAfterSeconds =
                configurationService.getBulkUserEmailStopNewRequestsAfterSeconds();

        List<CompletableFuture<Void>> futures =
                allUserSubjectIds.stream()
                        .map(
                                subjectId ->
                                        createEmailTask(
                                                subjectId,
                                                bulkEmailUserSendMode,
                                                executor,
                                                taskTimeoutSeconds,
                                                startTime,
                                                stopNewRequestsAfterSeconds,
                                                counters))
                        .toList();

        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
        executor.shutdownNow();

        LOG.info(
                "Bulk user email: completed. Total users: {}, Processed: {}, Skipped: {}, Unhandled exceptions: {}, Timed out: {}",
                allUserSubjectIds.size(),
                counters.processed().get(),
                counters.skipped().get(),
                counters.exceptions().get(),
                counters.timedOut().get());
        return null;
    }

    private BulkEmailUsersService.BulkEmailQueryResult getUserIdSubjectBatchPaginated(
            BulkEmailUserSendMode sendMode,
            Integer limit,
            Map<String, AttributeValue> exclusiveStartKey) {
        return switch (sendMode) {
            case PENDING ->
                    bulkEmailUsersService.getNSubjectIdsByStatus(
                            limit, BulkEmailStatus.PENDING, exclusiveStartKey);
            case NOTIFY_ERROR_RETRIES ->
                    bulkEmailUsersService.getNSubjectIdsByStatus(
                            limit, BulkEmailStatus.ERROR_SENDING_EMAIL, exclusiveStartKey);
            case DELIVERY_RECEIPT_TEMPORARY_FAILURE_RETRIES ->
                    bulkEmailUsersService.getNSubjectIdsByDeliveryReceiptStatus(
                            limit, DELIVERY_RECEIPT_STATUS_TEMPORARY_FAILURE, exclusiveStartKey);
            default -> throw new UnrecognisedSendModeException(sendMode.getValue());
        };
    }

    private CompletableFuture<Void> createEmailTask(
            String subjectId,
            BulkEmailUserSendMode sendMode,
            ExecutorService executor,
            int timeoutSeconds,
            long startTime,
            int stopNewRequestsAfterSeconds,
            TaskCounters counters) {
        return CompletableFuture.runAsync(
                        () -> {
                            long elapsedSeconds = (System.currentTimeMillis() - startTime) / 1000;
                            if (elapsedSeconds >= stopNewRequestsAfterSeconds) {
                                counters.skipped().incrementAndGet();
                                return;
                            }
                            bulkEmailSender.validateAndSendMessage(subjectId, sendMode);
                            counters.processed().incrementAndGet();
                        },
                        executor)
                .orTimeout(timeoutSeconds, TimeUnit.SECONDS)
                .exceptionally(
                        e -> {
                            if (e instanceof TimeoutException) {
                                counters.timedOut().incrementAndGet();
                                LOG.warn("Task timed out");
                            } else {
                                counters.exceptions().incrementAndGet();
                                LOG.error("Error sending bulk email", e);
                            }
                            return null;
                        });
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

    private record TaskCounters(
            AtomicInteger processed,
            AtomicInteger skipped,
            AtomicInteger timedOut,
            AtomicInteger exceptions) {
        TaskCounters() {
            this(
                    new AtomicInteger(),
                    new AtomicInteger(),
                    new AtomicInteger(),
                    new AtomicInteger());
        }
    }
}
