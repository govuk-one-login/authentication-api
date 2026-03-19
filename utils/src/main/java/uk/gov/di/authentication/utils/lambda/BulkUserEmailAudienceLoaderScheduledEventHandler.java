package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import net.minidev.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.exceptions.LambdaInvokerServiceException;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.LambdaInvokerService;
import uk.gov.di.authentication.shared.services.SystemService;
import uk.gov.di.authentication.utils.domain.BulkEmailType;
import uk.gov.di.authentication.utils.domain.DynamoTable;
import uk.gov.di.authentication.utils.helpers.BulkEmailBatchPauseHelper;
import uk.gov.di.authentication.utils.services.audienceloader.BulkEmailAudienceLoader;
import uk.gov.di.authentication.utils.services.audienceloader.InternationalNumbersForcedMfaResetBulkEmailAudienceLoader;
import uk.gov.di.authentication.utils.services.audienceloader.TermsAndConditionsBulkEmailAudienceLoader;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

public class BulkUserEmailAudienceLoaderScheduledEventHandler
        implements RequestHandler<ScheduledEvent, Void> {

    private static final Logger LOG =
            LogManager.getLogger(BulkUserEmailAudienceLoaderScheduledEventHandler.class);

    public static final String LAST_EVALUATED_KEY = "lastEvaluatedKey";
    public static final String GLOBAL_USERS_ADDED_COUNT = "globalUsersAddedCount";
    public static final String TABLE_TO_SCAN = "tableToScan";

    private final BulkEmailUsersService bulkEmailUsersService;

    private final ConfigurationService configurationService;

    private final BulkEmailAudienceLoader audienceLoader;

    private LambdaInvokerService lambdaInvokerService;

    public BulkUserEmailAudienceLoaderScheduledEventHandler() {
        this(ConfigurationService.getInstance());
        this.configurationService.setSystemService(new SystemService());
    }

    public BulkUserEmailAudienceLoaderScheduledEventHandler(
            BulkEmailUsersService bulkEmailUsersService,
            ConfigurationService configurationService,
            LambdaInvokerService lambdaInvokerService,
            BulkEmailAudienceLoader audienceLoader) {
        this.bulkEmailUsersService = bulkEmailUsersService;
        this.configurationService = configurationService;
        this.lambdaInvokerService = lambdaInvokerService;
        this.audienceLoader = audienceLoader;
    }

    public BulkUserEmailAudienceLoaderScheduledEventHandler(
            ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.bulkEmailUsersService = new BulkEmailUsersService(configurationService);
        this.lambdaInvokerService = new LambdaInvokerService(configurationService);

        DynamoService dynamoService = new DynamoService(configurationService);
        this.audienceLoader = createAudienceLoader(configurationService, dynamoService);
    }

    public void setLambdaInvoker(LambdaInvokerService lambdaInvokerService) {
        this.lambdaInvokerService = lambdaInvokerService;
    }

    private static BulkEmailAudienceLoader createAudienceLoader(
            ConfigurationService configurationService, DynamoService dynamoService) {
        BulkEmailType bulkUserEmailType =
                BulkEmailType.valueOf(configurationService.getBulkUserEmailType());

        if (bulkUserEmailType == BulkEmailType.TERMS_AND_CONDITIONS_BULK_EMAIL) {
            return new TermsAndConditionsBulkEmailAudienceLoader(
                    configurationService, dynamoService);
        }
        if (bulkUserEmailType == BulkEmailType.INTERNATIONAL_NUMBERS_FORCED_MFA_RESET_BULK_EMAIL) {
            return new InternationalNumbersForcedMfaResetBulkEmailAudienceLoader(dynamoService);
        }

        throw new UnsupportedOperationException(
                "Unsupported bulk user email type: " + bulkUserEmailType);
    }

    @Override
    public Void handleRequest(ScheduledEvent event, Context context) {
        LOG.info("Bulk User Email audience load triggered.");

        final long bulkUserEmailMaxAudienceLoadUserCount =
                configurationService.getBulkUserEmailMaxAudienceLoadUserCount();
        final long batchSize = configurationService.getBulkUserEmailAudienceLoadUserBatchSize();

        Map<String, AttributeValue> exclusiveStartKey = null;
        Long existingCountOfAddedUsers = 0L;
        DynamoTable tableToScan = DynamoTable.USER_PROFILE;

        audienceLoader.validateConfig();

        if (event.getDetail() != null && event.getDetail().containsKey(TABLE_TO_SCAN)) {
            tableToScan = DynamoTable.valueOf(event.getDetail().get(TABLE_TO_SCAN).toString());
        } else {
            LOG.info("Defaulting to scanning table: {}", tableToScan.name());
        }

        if (event.getDetail() != null && event.getDetail().containsKey(LAST_EVALUATED_KEY)) {
            String lastEvaluatedKey = event.getDetail().get(LAST_EVALUATED_KEY).toString();
            exclusiveStartKey =
                    Map.of("Email", AttributeValue.builder().s(lastEvaluatedKey).build());
        }

        if (event.getDetail() != null && event.getDetail().containsKey(GLOBAL_USERS_ADDED_COUNT)) {
            existingCountOfAddedUsers =
                    Long.parseLong(event.getDetail().get(GLOBAL_USERS_ADDED_COUNT).toString());
        }

        final Long remainingItemsLimit =
                bulkUserEmailMaxAudienceLoadUserCount - existingCountOfAddedUsers;
        final Long currentBatchSize = Math.min(batchSize, remainingItemsLimit);

        LOG.info(
                "Bulk User Email audience load parameters before batch: total users added so far {}, remaining items limit {}, batch size {}, scanning table {}",
                existingCountOfAddedUsers,
                remainingItemsLimit,
                currentBatchSize,
                tableToScan.name());

        AtomicLong itemCounter = new AtomicLong();
        AtomicReference<String> lastEmail = new AtomicReference<>();
        itemCounter.set(0);

        audienceLoader
                .loadUsers(exclusiveStartKey, tableToScan)
                .takeWhile(user -> (currentBatchSize > itemCounter.get()))
                .forEach(
                        user -> {
                            itemCounter.getAndIncrement();
                            bulkEmailUsersService.addUser(
                                    user.subjectID(), BulkEmailStatus.PENDING);
                            if (itemCounter.get() >= remainingItemsLimit) {
                                LOG.info(
                                        "Bulk User Email max audience load user count reached: {}. Stopping load.",
                                        itemCounter);
                            }
                            lastEmail.set(user.email());
                        });

        LOG.info(
                "Bulk User Email audience batch load complete.  Total users added this batch: {}",
                itemCounter);

        final long totalUsersAddedSoFar = itemCounter.get() + existingCountOfAddedUsers;
        DynamoTable nextTableToScan = tableToScan;

        if (itemCounter.get() == 0) {
            LOG.info(
                    "No items from table remaining to insert, finished import from table {}",
                    tableToScan.name());

            Optional<DynamoTable> nextTableToScanOptional = getNextTableToScan(tableToScan);
            if (nextTableToScanOptional.isEmpty()) {
                return null;
            }

            nextTableToScan = nextTableToScanOptional.get();
        } else if (itemCounter.get() >= remainingItemsLimit) {
            LOG.info(
                    "Bulk User Email max audience load max user count reached. Total users added {}. No further calls.",
                    totalUsersAddedSoFar);

            return null;
        }

        event.setDetail(
                buildReinvokeDetail(lastEmail.get(), totalUsersAddedSoFar, nextTableToScan));
        LOG.info(
                "Re-invoking lambda asynchronously. Total users added so far {}. Next table to scan: {}",
                totalUsersAddedSoFar,
                nextTableToScan.name());

        BulkEmailBatchPauseHelper.pauseBetweenBatches(
                configurationService.getBulkUserEmailAudienceLoadPauseDuration());

        reinvokeLambdaAsync(event);
        return null;
    }

    private void reinvokeLambdaAsync(ScheduledEvent event) {
        String lambdaName = configurationService.getBulkEmailLoaderLambdaName();

        if (lambdaName == null || lambdaName.isEmpty()) {
            throw new LambdaInvokerServiceException(
                    "BULK_USER_EMAIL_AUDIENCE_LOADER_LAMBDA_NAME environment variable not set");
        }

        JSONObject detail = new JSONObject();
        if (event.getDetail().containsKey(LAST_EVALUATED_KEY)) {
            detail.appendField(LAST_EVALUATED_KEY, event.getDetail().get(LAST_EVALUATED_KEY));
        }
        detail.appendField(
                GLOBAL_USERS_ADDED_COUNT, event.getDetail().get(GLOBAL_USERS_ADDED_COUNT));
        detail.appendField(TABLE_TO_SCAN, event.getDetail().get(TABLE_TO_SCAN));

        String jsonPayload = new JSONObject().appendField("detail", detail).toJSONString();
        lambdaInvokerService.invokeAsyncWithPayload(jsonPayload, lambdaName);
    }

    private Map<String, Object> buildReinvokeDetail(
            String lastEvaluatedKey, long globalUsersAddedCount, DynamoTable tableToScan) {
        if (lastEvaluatedKey != null) {
            return Map.of(
                    LAST_EVALUATED_KEY,
                    lastEvaluatedKey,
                    GLOBAL_USERS_ADDED_COUNT,
                    globalUsersAddedCount,
                    TABLE_TO_SCAN,
                    tableToScan);
        }
        return Map.of(GLOBAL_USERS_ADDED_COUNT, globalUsersAddedCount, TABLE_TO_SCAN, tableToScan);
    }

    private Optional<DynamoTable> getNextTableToScan(DynamoTable currentTable) {
        BulkEmailType bulkUserEmailType =
                BulkEmailType.valueOf(configurationService.getBulkUserEmailType());

        if (bulkUserEmailType == BulkEmailType.INTERNATIONAL_NUMBERS_FORCED_MFA_RESET_BULK_EMAIL) {
            if (currentTable != DynamoTable.USER_PROFILE) {
                return Optional.empty();
            }

            return Optional.of(DynamoTable.USER_CREDENTIALS);
        }

        return Optional.empty();
    }
}
