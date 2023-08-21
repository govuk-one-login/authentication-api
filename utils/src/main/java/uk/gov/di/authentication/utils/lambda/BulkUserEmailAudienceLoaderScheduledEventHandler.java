package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.LambdaInvokerService;

import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

public class BulkUserEmailAudienceLoaderScheduledEventHandler
        implements RequestHandler<ScheduledEvent, Void> {

    private static final Logger LOG =
            LogManager.getLogger(BulkUserEmailAudienceLoaderScheduledEventHandler.class);

    private final BulkEmailUsersService bulkEmailUsersService;

    private final DynamoService dynamoService;

    private final ConfigurationService configurationService;

    private final LambdaInvokerService lambdaInvokerService;

    public BulkUserEmailAudienceLoaderScheduledEventHandler() {
        this(ConfigurationService.getInstance());
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

    @Override
    public Void handleRequest(ScheduledEvent event, Context context) {
        LOG.info("Bulk User Email audience load triggered.");

        final long bulkUserEmailMaxAudienceLoadUserCount =
                configurationService.getBulkUserEmailMaxAudienceLoadUserCount();

        Map<String, AttributeValue> exclusiveStartKey = null;

        if (event.getDetail() != null && event.getDetail().containsKey("lastEvaluatedKey")) {
            String lastEvaluatedKey = event.getDetail().get("lastEvaluatedKey").toString();
            exclusiveStartKey =
                    Map.of("SubjectID", AttributeValue.builder().s(lastEvaluatedKey).build());
        }

        AtomicLong itemCounter = new AtomicLong();
        AtomicReference<String> lastSubjectId = new AtomicReference<>();
        itemCounter.set(0);
        dynamoService
                .getBulkUserEmailAudienceStream(exclusiveStartKey)
                .takeWhile(
                        userProfile -> (bulkUserEmailMaxAudienceLoadUserCount > itemCounter.get()))
                .forEach(
                        userProfile -> {
                            itemCounter.getAndIncrement();
                            bulkEmailUsersService.addUser(
                                    userProfile.getSubjectID(), BulkEmailStatus.PENDING);
                            LOG.info("Bulk User Email added item number: {}", itemCounter);
                            if (itemCounter.get() >= bulkUserEmailMaxAudienceLoadUserCount) {
                                LOG.info(
                                        "Bulk User Email max audience load user count reached: {}. Stopping load.",
                                        itemCounter);
                            }
                            lastSubjectId.set(userProfile.getSubjectID());
                        });

        LOG.info(
                "Bulk User Email audience batch load complete.  Total users added this batch: {}",
                itemCounter);

        if (itemCounter.get() == 0) {
            LOG.info("No items remaining to insert, finished import");
        } else {
            event.setDetail(Map.of("lastEvaluatedKey", lastSubjectId.get()));
            lambdaInvokerService.invokeWithPayload(event);
        }

        return null;
    }
}
