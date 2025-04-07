package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.KeysAndAttributes;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinTask;
import java.util.concurrent.TimeUnit;

import static java.text.MessageFormat.format;
import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoClient;

public class MFAMethodAnalysisHandler implements RequestHandler<String, Long> {

    private static final Logger LOG = LogManager.getLogger(MFAMethodAnalysisHandler.class);
    private final DynamoDbClient client;
    private final String userCredentialsTableName;
    private final String userProfileTableName;

    public MFAMethodAnalysisHandler(
            ConfigurationService configurationService, DynamoDbClient client) {
        this.client = client;
        userCredentialsTableName =
                format("{0}-user-credentials", configurationService.getEnvironment());
        userProfileTableName = format("{0}-user-profile", configurationService.getEnvironment());
    }

    public MFAMethodAnalysisHandler() {
        this(
                ConfigurationService.getInstance(),
                createDynamoClient(ConfigurationService.getInstance()));
    }

    @Override
    public Long handleRequest(String input, Context context) {
        long totalBatches = 0;
        long totalMatches = 0;
        long totalUserCredentialsFetched = 0;
        List<ForkJoinTask<Long>> batchTasks = new ArrayList<>();
        ForkJoinPool forkJoinPool = new ForkJoinPool(100);

        try {
            Map<String, AttributeValue> lastKey = null;
            do {
                Map<String, String> expressionAttributeNames = new HashMap<>();
                expressionAttributeNames.put("#mfa_methods", UserCredentials.ATTRIBUTE_MFA_METHODS);
                ScanRequest scanRequest =
                        ScanRequest.builder()
                                .tableName(userCredentialsTableName)
                                .filterExpression("attribute_exists(#mfa_methods)")
                                .expressionAttributeNames(expressionAttributeNames)
                                .exclusiveStartKey(lastKey)
                                .build();

                ScanResponse scanResponse = client.scan(scanRequest);

                List<String> currentBatchEmails = new ArrayList<>();
                for (Map<String, AttributeValue> userCredentialsItem : scanResponse.items()) {
                    totalUserCredentialsFetched++;
                    if (totalUserCredentialsFetched % 100000 == 0) {
                        LOG.info(
                                "Fetched {} user credentials records", totalUserCredentialsFetched);
                    }
                    String email = userCredentialsItem.get(UserCredentials.ATTRIBUTE_EMAIL).s();
                    currentBatchEmails.add(email);

                    if (currentBatchEmails.size() >= 100) {
                        totalBatches++;
                        queueBatch(forkJoinPool, currentBatchEmails, totalBatches, batchTasks);
                        currentBatchEmails = new ArrayList<>();
                    }
                }

                if (!currentBatchEmails.isEmpty()) {
                    totalBatches++;
                    queueBatch(forkJoinPool, currentBatchEmails, totalBatches, batchTasks);
                }

                lastKey = scanResponse.lastEvaluatedKey();
            } while (lastKey != null && !lastKey.isEmpty());

            for (ForkJoinTask<Long> task : batchTasks) {
                totalMatches += task.join();
            }

            gracefulPoolShutdown(forkJoinPool);
        } finally {
            forcePoolShutdown(forkJoinPool);
        }

        LOG.info("Found {} credentials/profile matches with AUTH_APP", totalMatches);
        return totalMatches;
    }

    private void gracefulPoolShutdown(ForkJoinPool forkJoinPool) {
        forkJoinPool.shutdown();
        try {
            if (!forkJoinPool.awaitTermination(15, TimeUnit.SECONDS)) {
                LOG.warn("ForkJoinPool did not terminate normally");
            }
        } catch (InterruptedException e) {
            LOG.error("ForkJoinPool termination interrupted", e);
            Thread.currentThread().interrupt();
        }
    }

    private void forcePoolShutdown(ForkJoinPool forkJoinPool) {
        if (!forkJoinPool.isShutdown()) {
            forkJoinPool.shutdownNow();
        }
    }

    private void queueBatch(
            ForkJoinPool forkJoinPool,
            List<String> emails,
            long batch,
            List<ForkJoinTask<Long>> batchTasks) {
        batchTasks.add(forkJoinPool.submit(() -> batchGetUserProfiles(batch, emails)));
    }

    private long batchGetUserProfiles(long batch, List<String> emails) {
        if (batch % 1000 == 0) {
            LOG.info("Executing user profile batch {}", batch);
        }

        if (emails.isEmpty()) {
            return 0;
        }

        Map<String, KeysAndAttributes> requestItems = new HashMap<>();
        List<Map<String, AttributeValue>> keys = new ArrayList<>();
        for (String email : emails) {
            Map<String, AttributeValue> key = new HashMap<>();
            key.put(UserProfile.ATTRIBUTE_EMAIL, AttributeValue.builder().s(email).build());
            keys.add(key);
        }
        requestItems.put(userProfileTableName, KeysAndAttributes.builder().keys(keys).build());

        BatchGetItemRequest batchGetItemRequest =
                BatchGetItemRequest.builder().requestItems(requestItems).build();

        BatchGetItemResponse batchGetItemResponse = client.batchGetItem(batchGetItemRequest);
        Map<String, List<Map<String, AttributeValue>>> results = batchGetItemResponse.responses();

        if (results.containsKey(userProfileTableName)) {
            return results.get(userProfileTableName).size();
        }
        return 0;
    }
}
