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
import uk.gov.di.authentication.utils.exceptions.IncludedTermsAndConditionsConfigMissingException;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

public class BulkUserEmailAudienceLoaderScheduledEventHandler
        implements RequestHandler<ScheduledEvent, Void> {

    private static final Logger LOG =
            LogManager.getLogger(BulkUserEmailAudienceLoaderScheduledEventHandler.class);

    public static final String LAST_EVALUATED_KEY = "lastEvaluatedKey";
    public static final String GLOBAL_USERS_ADDED_COUNT = "globalUsersAddedCount";

    private final BulkEmailUsersService bulkEmailUsersService;

    private final DynamoService dynamoService;

    private final ConfigurationService configurationService;

    private LambdaInvokerService lambdaInvokerService;

    public BulkUserEmailAudienceLoaderScheduledEventHandler() {
        this(ConfigurationService.getInstance());
        this.configurationService.setSystemService(new SystemService());
    }

    public BulkUserEmailAudienceLoaderScheduledEventHandler(
            BulkEmailUsersService bulkEmailUsersService,
            DynamoService dynamoService,
            ConfigurationService configurationService,
            LambdaInvokerService lambdaInvokerService) {
        this.bulkEmailUsersService = bulkEmailUsersService;
        this.dynamoService = dynamoService;
        this.configurationService = configurationService;
        this.lambdaInvokerService = lambdaInvokerService;
    }

    public BulkUserEmailAudienceLoaderScheduledEventHandler(
            ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.bulkEmailUsersService = new BulkEmailUsersService(configurationService);
        this.dynamoService = new DynamoService(configurationService);
        this.lambdaInvokerService = new LambdaInvokerService(configurationService);
    }

    public void setLambdaInvoker(LambdaInvokerService lambdaInvokerService) {
        this.lambdaInvokerService = lambdaInvokerService;
    }

    @Override
    public Void handleRequest(ScheduledEvent event, Context context) {
        LOG.info("Bulk User Email audience load triggered.");

        final long bulkUserEmailMaxAudienceLoadUserCount =
                configurationService.getBulkUserEmailMaxAudienceLoadUserCount();
        final long batchSize = configurationService.getBulkUserEmailAudienceLoadUserBatchSize();

        Map<String, AttributeValue> exclusiveStartKey = null;
        Long existingCountOfAddedUsers = 0L;

        List<String> includedTermsAndConditions =
                configurationService.getBulkUserEmailIncludedTermsAndConditions();
        if (includedTermsAndConditions == null || includedTermsAndConditions.isEmpty()) {
            throw new IncludedTermsAndConditionsConfigMissingException();
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
                "Bulk User Email audience load parameters before batch: total users added so far {}, remaining items limit {}, batch size {}",
                remainingItemsLimit,
                existingCountOfAddedUsers,
                currentBatchSize);

        AtomicLong itemCounter = new AtomicLong();
        AtomicReference<String> lastEmail = new AtomicReference<>();
        itemCounter.set(0);

        dynamoService
                .getBulkUserEmailAudienceStreamOnTermsAndConditionsVersion(
                        exclusiveStartKey, includedTermsAndConditions)
                .takeWhile(userProfile -> (currentBatchSize > itemCounter.get()))
                .forEach(
                        userProfile -> {
                            itemCounter.getAndIncrement();
                            bulkEmailUsersService.addUser(
                                    userProfile.getSubjectID(), BulkEmailStatus.PENDING);
                            LOG.info("Bulk User Email added item number: {}", itemCounter);
                            if (itemCounter.get() >= remainingItemsLimit) {
                                LOG.info(
                                        "Bulk User Email max audience load user count reached: {}. Stopping load.",
                                        itemCounter);
                            }
                            lastEmail.set(userProfile.getEmail());
                        });

        LOG.info(
                "Bulk User Email audience batch load complete.  Total users added this batch: {}",
                itemCounter);

        final long totalUsersAddedSoFar = itemCounter.get() + existingCountOfAddedUsers;
        if (itemCounter.get() == 0) {
            LOG.info("No items remaining to insert, finished import");
        } else if (itemCounter.get() >= remainingItemsLimit) {
            LOG.info(
                    "Bulk User Email max audience load max user count reached. Total users added {}",
                    totalUsersAddedSoFar);
        } else {
            event.setDetail(
                    Map.of(
                            LAST_EVALUATED_KEY,
                            lastEmail.get(),
                            GLOBAL_USERS_ADDED_COUNT,
                            totalUsersAddedSoFar));
            LOG.info(
                    "Bulk User Email re-invoke.  Total users added so far {}",
                    totalUsersAddedSoFar);
            reinvokeLambdaAsync(event);
        }

        return null;
    }

    private void reinvokeLambdaAsync(ScheduledEvent event) {
        String lambdaName = configurationService.getBulkEmailLoaderLambdaName();

        if (lambdaName == null || lambdaName.isEmpty()) {
            throw new LambdaInvokerServiceException(
                    "BULK_USER_EMAIL_AUDIENCE_LOADER_LAMBDA_NAME environment variable not set");
        }

        JSONObject detail = new JSONObject();
        detail.appendField(LAST_EVALUATED_KEY, event.getDetail().get(LAST_EVALUATED_KEY));
        detail.appendField(
                GLOBAL_USERS_ADDED_COUNT, event.getDetail().get(GLOBAL_USERS_ADDED_COUNT));

        String jsonPayload = new JSONObject().appendField("detail", detail).toJSONString();
        lambdaInvokerService.invokeAsyncWithPayload(jsonPayload, lambdaName);
    }
}
