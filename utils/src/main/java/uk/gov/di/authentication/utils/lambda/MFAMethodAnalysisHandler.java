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
import java.util.Optional;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinTask;
import java.util.concurrent.TimeUnit;

import static java.text.MessageFormat.format;
import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoClient;

public class MFAMethodAnalysisHandler implements RequestHandler<String, String> {

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
    public String handleRequest(String input, Context context) {
        MFAMethodAnalysis finalMFAMethodAnalysis = new MFAMethodAnalysis();
        long totalBatches = 0;
        long totalUserCredentialsFetched = 0;
        List<ForkJoinTask<MFAMethodAnalysis>> batchTasks = new ArrayList<>();
        ForkJoinPool forkJoinPool = new ForkJoinPool(100);

        try {
            Map<String, AttributeValue> lastKey = null;
            do {
                ScanRequest scanRequest =
                        ScanRequest.builder()
                                .tableName(userCredentialsTableName)
                                .filterExpression("attribute_exists(MfaMethods)")
                                .projectionExpression("Email,MfaMethods")
                                .exclusiveStartKey(lastKey)
                                .build();

                ScanResponse scanResponse = client.scan(scanRequest);

                List<UserCredentialsProfileJoin> currentBatch = new ArrayList<>();
                for (Map<String, AttributeValue> userCredentialsItem : scanResponse.items()) {
                    totalUserCredentialsFetched++;
                    if (totalUserCredentialsFetched % 100000 == 0) {
                        LOG.info(
                                "Fetched {} user credentials records", totalUserCredentialsFetched);
                    }

                    String email = userCredentialsItem.get(UserCredentials.ATTRIBUTE_EMAIL).s();

                    Map<String, AttributeValue> firstMfaMethod = null;
                    if (userCredentialsItem.containsKey("MfaMethods")) {
                        List<AttributeValue> mfaList = userCredentialsItem.get("MfaMethods").l();
                        if (!mfaList.isEmpty()) {
                            firstMfaMethod = mfaList.get(0).m();
                        }
                    }

                    Optional<Boolean> enabled =
                            Optional.ofNullable(firstMfaMethod)
                                    .map(map -> map.get("Enabled"))
                                    .map(AttributeValue::n)
                                    .map(n -> n.equals("1"));

                    Optional<Boolean> methodVerified =
                            Optional.ofNullable(firstMfaMethod)
                                    .map(map -> map.get("MethodVerified"))
                                    .map(AttributeValue::n)
                                    .map(n -> n.equals("1"));

                    currentBatch.add(
                            new UserCredentialsProfileJoin(email, enabled, methodVerified));

                    if (currentBatch.size() >= 100) {
                        totalBatches++;
                        queueBatch(forkJoinPool, currentBatch, totalBatches, batchTasks);
                        currentBatch = new ArrayList<>();
                    }
                }

                if (!currentBatch.isEmpty()) {
                    totalBatches++;
                    queueBatch(forkJoinPool, currentBatch, totalBatches, batchTasks);
                }

                lastKey = scanResponse.lastEvaluatedKey();
            } while (lastKey != null && !lastKey.isEmpty());

            for (ForkJoinTask<MFAMethodAnalysis> task : batchTasks) {
                MFAMethodAnalysis taskResult = task.join();
                finalMFAMethodAnalysis.incrementCountOfUsersAssessed(
                        taskResult.getCountOfUsersAssessed());
                finalMFAMethodAnalysis
                        .incrementCountOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods(
                                taskResult
                                        .getCountOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods());
            }

            gracefulPoolShutdown(forkJoinPool);
        } finally {
            forcePoolShutdown(forkJoinPool);
        }

        LOG.info("Found {} credentials/profile matches with AUTH_APP", finalMFAMethodAnalysis);
        return finalMFAMethodAnalysis.toString();
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
            List<UserCredentialsProfileJoin> batch,
            long batchNumber,
            List<ForkJoinTask<MFAMethodAnalysis>> batchTasks) {
        batchTasks.add(forkJoinPool.submit(() -> batchGetUserProfiles(batchNumber, batch)));
    }

    private MFAMethodAnalysis batchGetUserProfiles(
            long batchNumber, List<UserCredentialsProfileJoin> batch) {
        if (batchNumber % 1000 == 0) {
            LOG.info("Executing user profile batch {}", batchNumber);
        }

        if (batch.isEmpty()) {
            return new MFAMethodAnalysis();
        }

        Map<String, KeysAndAttributes> requestItems = new HashMap<>();
        List<Map<String, AttributeValue>> keys = new ArrayList<>();
        for (UserCredentialsProfileJoin item : batch) {
            Map<String, AttributeValue> key = new HashMap<>();
            key.put(
                    UserProfile.ATTRIBUTE_EMAIL,
                    AttributeValue.builder().s(item.getEmail()).build());
            keys.add(key);
        }
        requestItems.put(
                userProfileTableName,
                KeysAndAttributes.builder()
                        .keys(keys)
                        .projectionExpression("Email,PhoneNumberVerified")
                        .build());

        BatchGetItemRequest batchGetItemRequest =
                BatchGetItemRequest.builder().requestItems(requestItems).build();

        BatchGetItemResponse batchGetItemResponse = client.batchGetItem(batchGetItemRequest);
        List<Map<String, AttributeValue>> results =
                batchGetItemResponse.responses().get(userProfileTableName);

        for (Map<String, AttributeValue> item : results) {
            String email =
                    Optional.ofNullable(item.get("Email")).map(AttributeValue::s).orElse(null);

            if (email != null) {
                Optional<Boolean> phoneNumberVerified =
                        Optional.ofNullable(item.get("PhoneNumberVerified"))
                                .map(AttributeValue::n)
                                .map(n -> n.equals("1"));

                batch.stream()
                        .filter(user -> email.equalsIgnoreCase(user.getEmail()))
                        .findFirst()
                        .ifPresent(user -> user.setPhoneNumberVerified(phoneNumberVerified));
            }
        }

        MFAMethodAnalysis mfaMethodAnalysis = new MFAMethodAnalysis();
        mfaMethodAnalysis.incrementCountOfUsersAssessed(batch.size());
        mfaMethodAnalysis
                .incrementCountOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods(
                        batch.stream()
                                .filter(
                                        UserCredentialsProfileJoin
                                                ::userHasAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods)
                                .count());

        return mfaMethodAnalysis;
    }

    private static class UserCredentialsProfileJoin {
        private final String email;
        private final Optional<Boolean> enabled;
        private final Optional<Boolean> methodVerified;
        private Optional<Boolean> phoneNumberVerified = Optional.empty();

        public UserCredentialsProfileJoin(
                String email, Optional<Boolean> enabled, Optional<Boolean> methodVerified) {
            this.email = email;
            this.enabled = enabled;
            this.methodVerified = methodVerified;
        }

        public String getEmail() {
            return email;
        }

        public void setPhoneNumberVerified(Optional<Boolean> phoneNumberVerified) {
            this.phoneNumberVerified = phoneNumberVerified;
        }

        public boolean userHasAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods() {
            if (methodVerified.isEmpty() || phoneNumberVerified.isEmpty() || enabled.isEmpty()) {
                return false;
            }
            return !methodVerified.get() && !phoneNumberVerified.get() && enabled.get();
        }
    }

    private static class MFAMethodAnalysis {
        private long countOfUsersAssessed = 0;
        private long countOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods = 0;

        public long getCountOfUsersAssessed() {
            return countOfUsersAssessed;
        }

        public void incrementCountOfUsersAssessed(long i) {
            this.countOfUsersAssessed += i;
        }

        public long getCountOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods() {
            return countOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods;
        }

        public void incrementCountOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods(
                long i) {
            this.countOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods += i;
        }

        @Override
        public String toString() {
            return "MFAMethodAnalysis{"
                    + "countOfUsersAssessed="
                    + countOfUsersAssessed
                    + ", countOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods="
                    + countOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods
                    + '}';
        }
    }
}
