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
import uk.gov.di.authentication.shared.helpers.PhoneNumberHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinTask;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static java.text.MessageFormat.format;
import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoClient;

public class MFAMethodAnalysisHandler implements RequestHandler<Object, String> {

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
    public String handleRequest(Object input, Context context) {
        List<ForkJoinTask<MFAMethodAnalysis>> parallelTasks = new ArrayList<>();
        ForkJoinPool forkJoinPool = new ForkJoinPool(100);
        try {
            fetchPhoneNumberVerifiedStatistics(forkJoinPool, parallelTasks);
            fetchUserCredentialsAndProfileStatistics(forkJoinPool, parallelTasks);
            Pool.gracefulPoolShutdown(forkJoinPool);
            String analysis = combineTaskResults(parallelTasks).toString();
            LOG.info("Analysis result: {}", analysis);
            return analysis;
        } finally {
            Pool.forcePoolShutdown(forkJoinPool);
        }
    }

    private static MFAMethodAnalysis combineTaskResults(
            List<ForkJoinTask<MFAMethodAnalysis>> parallelTasks) {
        MFAMethodAnalysis finalMFAMethodAnalysis = new MFAMethodAnalysis();
        for (ForkJoinTask<MFAMethodAnalysis> task : parallelTasks) {
            MFAMethodAnalysis taskResult = task.join();
            finalMFAMethodAnalysis.incrementCountOfAuthAppUsersAssessed(
                    taskResult.getCountOfAuthAppUsersAssessed());
            finalMFAMethodAnalysis
                    .incrementCountOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods(
                            taskResult
                                    .getCountOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods());
            finalMFAMethodAnalysis.mergeAttributeCombinationsForAuthAppUsersCount(
                    taskResult.getAttributeCombinationsForAuthAppUsersCount());
            finalMFAMethodAnalysis.mergeMfaMethodPriorityIdentifierCombinations(
                    taskResult.getMfaMethodPriorityIdentifierCombinations());
            finalMFAMethodAnalysis.incrementCountOfPhoneNumberUsersAssessed(
                    taskResult.getCountOfPhoneNumberUsersAssessed());
            finalMFAMethodAnalysis.incrementCountOfUsersWithVerifiedPhoneNumber(
                    taskResult.getCountOfUsersWithVerifiedPhoneNumber());
            finalMFAMethodAnalysis.mergePhoneDestinationCounts(
                    taskResult.getPhoneDestinationCounts());
        }
        return finalMFAMethodAnalysis;
    }

    private void fetchPhoneNumberVerifiedStatistics(
            ForkJoinPool forkJoinPool, List<ForkJoinTask<MFAMethodAnalysis>> parallelTasks) {
        parallelTasks.add(
                forkJoinPool.submit(
                        () -> {
                            Map<String, AttributeValue> lastKey = null;
                            int totalCount = 0;
                            int totalScanned = 0;
                            Map<String, Long> destinationCounts = new HashMap<>();
                            int logThreshold = 100_000;
                            int lastLoggedAt = 0;

                            do {
                                ScanRequest request =
                                        ScanRequest.builder()
                                                .tableName(userProfileTableName)
                                                .indexName("PhoneNumberIndex")
                                                .filterExpression("PhoneNumberVerified = :v")
                                                .expressionAttributeValues(
                                                        Map.of(
                                                                ":v",
                                                                AttributeValue.builder()
                                                                        .n("1")
                                                                        .build()))
                                                .projectionExpression("PhoneNumber")
                                                .exclusiveStartKey(lastKey)
                                                .build();

                                ScanResponse response = client.scan(request);

                                for (Map<String, AttributeValue> item : response.items()) {
                                    String phoneNumber = item.get("PhoneNumber").s();
                                    String destinationType =
                                            PhoneNumberHelper.maybeGetCountry(phoneNumber)
                                                    .map(
                                                            country ->
                                                                    "44".equals(country)
                                                                            ? "DOMESTIC"
                                                                            : "INTERNATIONAL")
                                                    .orElse("UNKNOWN");
                                    destinationCounts.merge(destinationType, 1L, Long::sum);
                                }

                                totalCount += response.count();
                                totalScanned += response.scannedCount();
                                lastKey = response.lastEvaluatedKey();

                                if (totalScanned - lastLoggedAt >= logThreshold) {
                                    LOG.info("Fetched {} phone number index records", totalScanned);
                                    lastLoggedAt = totalScanned - (totalScanned % logThreshold);
                                }
                            } while (lastKey != null && !lastKey.isEmpty());

                            MFAMethodAnalysis analysis = new MFAMethodAnalysis();
                            analysis.incrementCountOfPhoneNumberUsersAssessed(totalScanned);
                            analysis.incrementCountOfUsersWithVerifiedPhoneNumber(totalCount);
                            analysis.mergePhoneDestinationCounts(destinationCounts);

                            return analysis;
                        }));
    }

    private void fetchUserCredentialsAndProfileStatistics(
            ForkJoinPool forkJoinPool, List<ForkJoinTask<MFAMethodAnalysis>> parallelTasks) {
        long totalBatches = 0;
        long totalUserCredentialsFetched = 0;
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
                    LOG.info("Fetched {} user credentials records", totalUserCredentialsFetched);
                }

                String email = userCredentialsItem.get(UserCredentials.ATTRIBUTE_EMAIL).s();

                Map<String, AttributeValue> firstMfaMethod = null;
                List<String> mfaMethodPriorityIdentifiers = new ArrayList<>();
                if (userCredentialsItem.containsKey("MfaMethods")) {
                    List<AttributeValue> mfaList = userCredentialsItem.get("MfaMethods").l();
                    if (!mfaList.isEmpty()) {
                        firstMfaMethod = mfaList.get(0).m();
                    }
                    for (AttributeValue mfaMethodValue : mfaList) {
                        Map<String, AttributeValue> mfaMethod = mfaMethodValue.m();
                        String mfaMethodPriority =
                                Optional.ofNullable(mfaMethod.get("PriorityIdentifier"))
                                        .map(AttributeValue::s)
                                        .orElse(null);
                        mfaMethodPriorityIdentifiers.add(mfaMethodPriority);
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
                        new UserCredentialsProfileJoin(
                                email, enabled, methodVerified, mfaMethodPriorityIdentifiers));

                if (currentBatch.size() >= 100) {
                    totalBatches++;
                    long finalTotalBatches = totalBatches;
                    List<UserCredentialsProfileJoin> finalCurrentBatch = currentBatch;
                    parallelTasks.add(
                            forkJoinPool.submit(
                                    () ->
                                            batchGetUserProfiles(
                                                    finalTotalBatches, finalCurrentBatch)));
                    currentBatch = new ArrayList<>();
                }
            }

            if (!currentBatch.isEmpty()) {
                totalBatches++;
                long finalTotalBatches = totalBatches;
                List<UserCredentialsProfileJoin> finalCurrentBatch = currentBatch;
                parallelTasks.add(
                        forkJoinPool.submit(
                                () -> batchGetUserProfiles(finalTotalBatches, finalCurrentBatch)));
            }

            lastKey = scanResponse.lastEvaluatedKey();
        } while (lastKey != null && !lastKey.isEmpty());
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
        mfaMethodAnalysis.incrementCountOfAuthAppUsersAssessed(batch.size());
        mfaMethodAnalysis
                .incrementCountOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods(
                        batch.stream()
                                .filter(
                                        UserCredentialsProfileJoin
                                                ::userHasAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods)
                                .count());

        Map<UserCredentialsProfileJoin.AttributeCombinations, Long> attributeCombinationsCount =
                new HashMap<>();
        for (UserCredentialsProfileJoin item : batch) {
            attributeCombinationsCount.merge(item.getAttributeCombinations(), 1L, Long::sum);
        }
        mfaMethodAnalysis.mergeAttributeCombinationsForAuthAppUsersCount(
                attributeCombinationsCount);

        Map<String, Long> mfaMethodPriorityCombinationsCount = new HashMap<>();
        for (UserCredentialsProfileJoin item : batch) {
            String combinationKey =
                    item.getMfaMethodPriorityIdentifiers().isEmpty()
                            ? "no-methods"
                            : item.getMfaMethodPriorityIdentifiers().stream()
                                    .map(s -> s == null ? "null" : s)
                                    .collect(Collectors.joining(","));
            mfaMethodPriorityCombinationsCount.merge(combinationKey, 1L, Long::sum);
        }
        mfaMethodAnalysis.mergeMfaMethodPriorityIdentifierCombinations(
                mfaMethodPriorityCombinationsCount);

        return mfaMethodAnalysis;
    }

    private static class Pool {
        private static void gracefulPoolShutdown(ForkJoinPool forkJoinPool) {
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

        private static void forcePoolShutdown(ForkJoinPool forkJoinPool) {
            if (!forkJoinPool.isShutdown()) {
                forkJoinPool.shutdownNow();
            }
        }
    }

    private static class UserCredentialsProfileJoin {
        public static final String EMPTY = "empty";
        private final String email;
        private final Optional<Boolean> authAppEnabled;
        private final Optional<Boolean> authAppMethodVerified;
        private Optional<Boolean> phoneNumberVerified = Optional.empty();
        private final List<String> mfaMethodPriorityIdentifiers;

        public UserCredentialsProfileJoin(
                String email,
                Optional<Boolean> authAppEnabled,
                Optional<Boolean> authAppMethodVerified,
                List<String> mfaMethodPriorityIdentifiers) {
            this.email = email;
            this.authAppEnabled = authAppEnabled;
            this.authAppMethodVerified = authAppMethodVerified;
            this.mfaMethodPriorityIdentifiers = mfaMethodPriorityIdentifiers;
        }

        public String getEmail() {
            return email;
        }

        public void setPhoneNumberVerified(Optional<Boolean> phoneNumberVerified) {
            this.phoneNumberVerified = phoneNumberVerified;
        }

        public List<String> getMfaMethodPriorityIdentifiers() {
            return mfaMethodPriorityIdentifiers;
        }

        public boolean userHasAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods() {
            if (authAppMethodVerified.isEmpty()
                    || phoneNumberVerified.isEmpty()
                    || authAppEnabled.isEmpty()) {
                return false;
            }
            return !authAppMethodVerified.get()
                    && !phoneNumberVerified.get()
                    && authAppEnabled.get();
        }

        public AttributeCombinations getAttributeCombinations() {
            return new AttributeCombinations(
                    authAppEnabled.map(String::valueOf).orElse(EMPTY),
                    authAppMethodVerified.map(String::valueOf).orElse(EMPTY),
                    phoneNumberVerified.map(String::valueOf).orElse(EMPTY));
        }

        public record AttributeCombinations(
                String authAppEnabled, String authAppMethodVerified, String phoneNumberVerified) {}
    }

    private static class MFAMethodAnalysis {
        private long countOfAuthAppUsersAssessed = 0;
        private long countOfPhoneNumberUsersAssessed = 0;
        private long countOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods = 0;
        private long countOfUsersWithVerifiedPhoneNumber = 0;
        private final Map<String, Long> phoneDestinationCounts = new HashMap<>();
        private final Map<UserCredentialsProfileJoin.AttributeCombinations, Long>
                attributeCombinationsForAuthAppUsersCount = new HashMap<>();
        private final Map<String, Long> mfaMethodPriorityIdentifierCombinations = new HashMap<>();

        public long getCountOfAuthAppUsersAssessed() {
            return countOfAuthAppUsersAssessed;
        }

        public void incrementCountOfAuthAppUsersAssessed(long i) {
            this.countOfAuthAppUsersAssessed += i;
        }

        public long getCountOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods() {
            return countOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods;
        }

        public void incrementCountOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods(
                long i) {
            this.countOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods += i;
        }

        public long getCountOfPhoneNumberUsersAssessed() {
            return countOfPhoneNumberUsersAssessed;
        }

        public void incrementCountOfPhoneNumberUsersAssessed(long i) {
            this.countOfPhoneNumberUsersAssessed += i;
        }

        public long getCountOfUsersWithVerifiedPhoneNumber() {
            return countOfUsersWithVerifiedPhoneNumber;
        }

        public void incrementCountOfUsersWithVerifiedPhoneNumber(long i) {
            this.countOfUsersWithVerifiedPhoneNumber += i;
        }

        public Map<String, Long> getPhoneDestinationCounts() {
            return phoneDestinationCounts;
        }

        public void mergePhoneDestinationCounts(Map<String, Long> counts) {
            for (Map.Entry<String, Long> entry : counts.entrySet()) {
                this.phoneDestinationCounts.merge(entry.getKey(), entry.getValue(), Long::sum);
            }
        }

        public Map<UserCredentialsProfileJoin.AttributeCombinations, Long>
                getAttributeCombinationsForAuthAppUsersCount() {
            return attributeCombinationsForAuthAppUsersCount;
        }

        public void mergeAttributeCombinationsForAuthAppUsersCount(
                Map<UserCredentialsProfileJoin.AttributeCombinations, Long>
                        attributeCombinationsCount) {
            for (Map.Entry<UserCredentialsProfileJoin.AttributeCombinations, Long> item :
                    attributeCombinationsCount.entrySet()) {
                this.attributeCombinationsForAuthAppUsersCount.merge(
                        item.getKey(), item.getValue(), Long::sum);
            }
        }

        public Map<String, Long> getMfaMethodPriorityIdentifierCombinations() {
            return mfaMethodPriorityIdentifierCombinations;
        }

        public void mergeMfaMethodPriorityIdentifierCombinations(Map<String, Long> combinations) {
            for (Map.Entry<String, Long> entry : combinations.entrySet()) {
                this.mfaMethodPriorityIdentifierCombinations.merge(
                        entry.getKey(), entry.getValue(), Long::sum);
            }
        }

        @Override
        public String toString() {
            return "MFAMethodAnalysis{"
                    + "countOfAuthAppUsersAssessed="
                    + countOfAuthAppUsersAssessed
                    + ", countOfPhoneNumberUsersAssessed="
                    + countOfPhoneNumberUsersAssessed
                    + ", countOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods="
                    + countOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods
                    + ", countOfUsersWithVerifiedPhoneNumber="
                    + countOfUsersWithVerifiedPhoneNumber
                    + ", phoneDestinationCounts="
                    + phoneDestinationCounts
                    + ", attributeCombinationsForAuthAppUsersCount="
                    + attributeCombinationsForAuthAppUsersCount
                    + ", mfaMethodPriorityIdentifierCombinations="
                    + mfaMethodPriorityIdentifierCombinations
                    + '}';
        }
    }
}
