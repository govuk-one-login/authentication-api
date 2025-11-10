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
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
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

    public static final String ABSENT_ATTRIBUTE = "absent_attribute";
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

            MFAMethodAnalysis combinedResults = combineTaskResults(parallelTasks);
            String analysis = combinedResults.toString();
            LOG.info("Analysis result: {}", analysis);

            String userProfileRetrievalAnalysis =
                    String.format(
                            "User profile retrieval failures: userProfile items could not be retrieved for %,d accounts.",
                            combinedResults.getMissingUserProfileCount());
            LOG.info(userProfileRetrievalAnalysis);

            return String.format("%s %s", analysis, userProfileRetrievalAnalysis);
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

            finalMFAMethodAnalysis.incrementCountOfAccountsWithoutAnyMfaMethods(
                    taskResult.getCountOfAccountsWithoutAnyMfaMethods());
            finalMFAMethodAnalysis.incrementCountOfPhoneNumberUsersAssessed(
                    taskResult.getCountOfPhoneNumberUsersAssessed());
            finalMFAMethodAnalysis.incrementCountOfUsersWithVerifiedPhoneNumber(
                    taskResult.getCountOfUsersWithVerifiedPhoneNumber());
            finalMFAMethodAnalysis.mergePhoneDestinationCounts(
                    taskResult.getPhoneDestinationCounts());
            finalMFAMethodAnalysis.mergeMfaMethodDetailsCombinations(
                    taskResult.getMfaMethodDetailsCombinations());
            finalMFAMethodAnalysis.incrementCountOfUsersWithMfaMethodsMigrated(
                    taskResult.getCountOfUsersWithMfaMethodsMigrated());
            finalMFAMethodAnalysis.incrementCountOfUsersWithoutMfaMethodsMigrated(
                    taskResult.getCountOfUsersWithoutMfaMethodsMigrated());
            finalMFAMethodAnalysis.incrementMissingUserProfileCount(
                    taskResult.getMissingUserProfileCount());
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
            ScanResponse scanResponse = scanUserCredentials(lastKey);
            List<UserCredentialsProfileJoin> currentBatch = new ArrayList<>();

            for (Map<String, AttributeValue> userCredentialsItem : scanResponse.items()) {
                totalUserCredentialsFetched++;
                logProgressIfNeeded(totalUserCredentialsFetched);

                UserCredentialsProfileJoin userJoin =
                        createUserCredentialsProfileJoin(userCredentialsItem);
                currentBatch.add(userJoin);

                if (currentBatch.size() >= 100) {
                    totalBatches++;
                    submitBatch(
                            forkJoinPool,
                            parallelTasks,
                            new ArrayList<>(currentBatch),
                            totalBatches);
                    currentBatch = new ArrayList<>();
                }
            }

            if (!currentBatch.isEmpty()) {
                totalBatches++;
                submitBatch(forkJoinPool, parallelTasks, currentBatch, totalBatches);
            }

            lastKey = scanResponse.lastEvaluatedKey();
        } while (lastKey != null && !lastKey.isEmpty());
    }

    private ScanResponse scanUserCredentials(Map<String, AttributeValue> lastKey) {
        ScanRequest scanRequest =
                ScanRequest.builder()
                        .tableName(userCredentialsTableName)
                        .projectionExpression("Email,MfaMethods")
                        .exclusiveStartKey(lastKey)
                        .build();
        return client.scan(scanRequest);
    }

    private void logProgressIfNeeded(long totalFetched) {
        if (totalFetched % 100000 == 0) {
            LOG.info("Fetched {} user credentials records", totalFetched);
        }
    }

    private UserCredentialsProfileJoin createUserCredentialsProfileJoin(
            Map<String, AttributeValue> userCredentialsItem) {
        String email = userCredentialsItem.get(UserCredentials.ATTRIBUTE_EMAIL).s();

        List<MfaMethodDetails> mfaMethodDetails = extractMfaMethodDetails(userCredentialsItem);

        return new UserCredentialsProfileJoin(email, mfaMethodDetails);
    }

    private List<MfaMethodDetails> extractMfaMethodDetails(
            Map<String, AttributeValue> userCredentialsItem) {
        if (!userCredentialsItem.containsKey("MfaMethods")) {
            return new ArrayList<>();
        }

        List<AttributeValue> mfaList = userCredentialsItem.get("MfaMethods").l();

        // NOTE: ABSENT_ATTRIBUTE constant indicates absent DynamoDB attribute; string "null"
        // represents existing attribute with "null" value.
        return mfaList.stream()
                .map(AttributeValue::m)
                .map(
                        mfaMethod -> {
                            String mfaMethodType =
                                    Optional.ofNullable(mfaMethod.get("MfaMethodType"))
                                            .map(AttributeValue::s)
                                            .orElse(ABSENT_ATTRIBUTE);

                            return new MfaMethodDetails(
                                    Optional.ofNullable(mfaMethod.get("PriorityIdentifier"))
                                            .map(AttributeValue::s)
                                            .orElse(ABSENT_ATTRIBUTE),
                                    mfaMethodType,
                                    extractBooleanAttribute(mfaMethod, "Enabled"),
                                    extractBooleanAttribute(mfaMethod, "MethodVerified"),
                                    hasAuthAppCredential(mfaMethod, mfaMethodType));
                        })
                .toList();
    }

    private static Optional<Boolean> extractBooleanAttribute(
            Map<String, AttributeValue> attributeMap, String attributeName) {
        return Optional.ofNullable(attributeMap.get(attributeName))
                .map(AttributeValue::n)
                .map(n -> n.equals("1"));
    }

    private static Optional<Boolean> hasAuthAppCredential(
            Map<String, AttributeValue> attributeMap, String mfaMethodType) {
        if (!MFAMethodType.AUTH_APP.name().equals(mfaMethodType)) {
            return Optional.empty();
        }

        AttributeValue credential = attributeMap.get("CredentialValue");

        return Optional.of(isAttributeNonEmptyString(credential));
    }

    private void submitBatch(
            ForkJoinPool forkJoinPool,
            List<ForkJoinTask<MFAMethodAnalysis>> parallelTasks,
            List<UserCredentialsProfileJoin> batch,
            long batchNumber) {
        parallelTasks.add(forkJoinPool.submit(() -> batchGetUserProfiles(batchNumber, batch)));
    }

    private static boolean isAttributeNonEmptyString(AttributeValue value) {
        return Optional.ofNullable(value)
                .map(AttributeValue::s)
                .map(s -> !s.trim().isEmpty())
                .orElse(false);
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
                        .projectionExpression(
                                "Email,PhoneNumber,PhoneNumberVerified,mfaMethodsMigrated")
                        .build());

        BatchGetItemRequest batchGetItemRequest =
                BatchGetItemRequest.builder().requestItems(requestItems).build();

        BatchGetItemResponse batchGetItemResponse = client.batchGetItem(batchGetItemRequest);
        List<Map<String, AttributeValue>> results =
                batchGetItemResponse.responses().get(userProfileTableName);

        int missingCount = batch.size() - results.size();

        for (Map<String, AttributeValue> item : results) {
            String email =
                    Optional.ofNullable(item.get("Email")).map(AttributeValue::s).orElse(null);

            if (email != null) {
                Optional<Boolean> phoneNumberVerified =
                        Optional.ofNullable(item.get("PhoneNumberVerified"))
                                .map(AttributeValue::n)
                                .map(n -> n.equals("1"));

                boolean mfaMethodsMigrated =
                        Optional.ofNullable(item.get("mfaMethodsMigrated"))
                                .map(AttributeValue::bool)
                                .orElse(false);

                batch.stream()
                        .filter(user -> email.equalsIgnoreCase(user.getEmail()))
                        .findFirst()
                        .ifPresent(
                                user -> {
                                    user.setPhoneNumberVerified(phoneNumberVerified);
                                    user.setMfaMethodsMigrated(Optional.of(mfaMethodsMigrated));
                                    user.setHasPhoneNumber(
                                            isAttributeNonEmptyString(item.get("PhoneNumber")));
                                });
            }
        }

        MFAMethodAnalysis mfaMethodAnalysis = new MFAMethodAnalysis();
        mfaMethodAnalysis.incrementCountOfAuthAppUsersAssessed(
                batch.stream().filter(UserCredentialsProfileJoin::hasActiveAuthApp).count());
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

        Map<MfaMethodDetailsCombinationKey, Long> mfaMethodDetailsCombinations = new HashMap<>();
        long accountsWithoutAnyMfaMethods = 0;
        long usersWithMfaMethodsMigrated = 0;
        long usersWithoutMfaMethodsMigrated = 0;
        for (UserCredentialsProfileJoin item : batch) {
            if (item.hasNoMfaMethods()) {
                accountsWithoutAnyMfaMethods++;
            }
            if (item.getMfaMethodsMigrated().orElse(false)) {
                usersWithMfaMethodsMigrated++;
            } else {
                usersWithoutMfaMethodsMigrated++;
            }

            List<MfaMethodOutput> outputMethods =
                    item.getMfaMethodDetails().stream().map(MfaMethodDetails::toOutput).toList();
            boolean areMfaMethodsMigrated = item.getMfaMethodsMigrated().orElse(false);
            MfaMethodDetailsCombinationKey key =
                    new MfaMethodDetailsCombinationKey(outputMethods, areMfaMethodsMigrated);
            mfaMethodDetailsCombinations.merge(key, 1L, Long::sum);
        }
        mfaMethodAnalysis.incrementCountOfAccountsWithoutAnyMfaMethods(
                accountsWithoutAnyMfaMethods);
        mfaMethodAnalysis.incrementCountOfUsersWithMfaMethodsMigrated(usersWithMfaMethodsMigrated);
        mfaMethodAnalysis.incrementCountOfUsersWithoutMfaMethodsMigrated(
                usersWithoutMfaMethodsMigrated);
        mfaMethodAnalysis.mergeMfaMethodDetailsCombinations(mfaMethodDetailsCombinations);
        mfaMethodAnalysis.incrementMissingUserProfileCount(missingCount);

        return mfaMethodAnalysis;
    }

    private record MfaMethodDetails(
            String priorityIdentifier,
            String mfaMethodType,
            Optional<Boolean> enabled,
            Optional<Boolean> methodVerified,
            Optional<Boolean> hasAuthAppCredential) {

        public MfaMethodOutput toOutput() {
            return new MfaMethodOutput(priorityIdentifier, mfaMethodType);
        }
    }

    private record MfaMethodOutput(String priorityIdentifier, String mfaMethodType) {}

    private record MfaMethodDetailsCombinationKey(
            List<MfaMethodOutput> methods, boolean areMfaMethodsMigrated) {}

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
        private Optional<Boolean> hasAuthAppCredential;
        private Optional<Boolean> authAppEnabled;
        private Optional<Boolean> authAppMethodVerified;
        private boolean hasPhoneNumber;
        private Optional<Boolean> phoneNumberVerified = Optional.empty();
        private Optional<Boolean> mfaMethodsMigrated = Optional.empty();
        private final List<MfaMethodDetails> mfaMethodDetails;

        public UserCredentialsProfileJoin(String email, List<MfaMethodDetails> mfaMethodDetails) {
            this.email = email;
            this.mfaMethodDetails = mfaMethodDetails;

            setAuthAppAttributes();
        }

        private void setAuthAppAttributes() {
            Optional<MfaMethodDetails> authApp =
                    mfaMethodDetails.stream()
                            .filter(m -> MFAMethodType.AUTH_APP.name().equals(m.mfaMethodType()))
                            .findFirst();

            this.authAppEnabled = authApp.flatMap(MfaMethodDetails::enabled);
            this.authAppMethodVerified = authApp.flatMap(MfaMethodDetails::methodVerified);
            this.hasAuthAppCredential = authApp.flatMap(MfaMethodDetails::hasAuthAppCredential);
        }

        public String getEmail() {
            return email;
        }

        public void setPhoneNumberVerified(Optional<Boolean> phoneNumberVerified) {
            this.phoneNumberVerified = phoneNumberVerified;
        }

        public void setMfaMethodsMigrated(Optional<Boolean> mfaMethodsMigrated) {
            this.mfaMethodsMigrated = mfaMethodsMigrated;
        }

        public void setHasPhoneNumber(boolean hasPhoneNumber) {
            this.hasPhoneNumber = hasPhoneNumber;
        }

        public Optional<Boolean> getMfaMethodsMigrated() {
            return mfaMethodsMigrated;
        }

        public List<MfaMethodDetails> getMfaMethodDetails() {
            return mfaMethodDetails;
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

        public boolean hasActiveAuthApp() {
            return authAppEnabled.orElse(false)
                    && authAppMethodVerified.orElse(false)
                    && hasAuthAppCredential.orElse(false);
        }

        public boolean hasNoMfaMethods() {
            // If MFA methods have been migrated, check the new MfaMethods attribute
            if (mfaMethodsMigrated.orElse(false)) {
                return mfaMethodDetails.isEmpty();
            }

            // If not migrated, check both old auth app attributes and phone number verification
            boolean hasAuthApp = hasActiveAuthApp();
            boolean hasSms = hasPhoneNumber && phoneNumberVerified.orElse(false);

            return !hasAuthApp && !hasSms;
        }

        public record MfaMethodPriorityAndTypeAttributeCombinations(
                String priorityIdentifier, String mfaMethodType) {}

        public record AttributeCombinations(
                String authAppEnabled, String authAppMethodVerified, String phoneNumberVerified) {}

        // NOTE: Using a record to format nicely in output
        public record MfaMethodPriorityCombination(String methods) {}
    }

    private static class MFAMethodAnalysis {
        private long countOfAuthAppUsersAssessed = 0;
        private long countOfPhoneNumberUsersAssessed = 0;
        private long countOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods = 0;
        private long countOfUsersWithVerifiedPhoneNumber = 0;
        private long countOfAccountsWithoutAnyMfaMethods = 0;
        private long countOfUsersWithMfaMethodsMigrated = 0;
        private long countOfUsersWithoutMfaMethodsMigrated = 0;
        private long missingUserProfileCount = 0;
        private final Map<String, Long> phoneDestinationCounts = new HashMap<>();
        private final Map<UserCredentialsProfileJoin.AttributeCombinations, Long>
                attributeCombinationsForAuthAppUsersCount = new HashMap<>();
        private final Map<MfaMethodDetailsCombinationKey, Long> mfaMethodDetailsCombinations =
                new HashMap<>();

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

        public long getCountOfAccountsWithoutAnyMfaMethods() {
            return countOfAccountsWithoutAnyMfaMethods;
        }

        public void incrementCountOfAccountsWithoutAnyMfaMethods(long i) {
            this.countOfAccountsWithoutAnyMfaMethods += i;
        }

        public long getCountOfUsersWithMfaMethodsMigrated() {
            return countOfUsersWithMfaMethodsMigrated;
        }

        public void incrementCountOfUsersWithMfaMethodsMigrated(long i) {
            this.countOfUsersWithMfaMethodsMigrated += i;
        }

        public long getCountOfUsersWithoutMfaMethodsMigrated() {
            return countOfUsersWithoutMfaMethodsMigrated;
        }

        public void incrementCountOfUsersWithoutMfaMethodsMigrated(long i) {
            this.countOfUsersWithoutMfaMethodsMigrated += i;
        }

        public long getMissingUserProfileCount() {
            return missingUserProfileCount;
        }

        public void incrementMissingUserProfileCount(long i) {
            this.missingUserProfileCount += i;
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

        public Map<MfaMethodDetailsCombinationKey, Long> getMfaMethodDetailsCombinations() {
            return mfaMethodDetailsCombinations;
        }

        public Map<UserCredentialsProfileJoin.MfaMethodPriorityCombination, Long>
                getMfaMethodPriorityIdentifierCombinations() {
            return mfaMethodDetailsCombinations.entrySet().stream()
                    .collect(
                            Collectors.groupingBy(
                                    entry ->
                                            new UserCredentialsProfileJoin
                                                    .MfaMethodPriorityCombination(
                                                    entry.getKey().methods().stream()
                                                            .map(
                                                                    MfaMethodOutput
                                                                            ::priorityIdentifier)
                                                            .map(s -> s == null ? "null" : s)
                                                            .collect(Collectors.joining(","))),
                                    Collectors.summingLong(Map.Entry::getValue)));
        }

        public void mergeMfaMethodDetailsCombinations(
                Map<MfaMethodDetailsCombinationKey, Long> combinations) {
            for (Map.Entry<MfaMethodDetailsCombinationKey, Long> entry : combinations.entrySet()) {
                this.mfaMethodDetailsCombinations.merge(
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
                    + ", countOfAccountsWithoutAnyMfaMethods="
                    + countOfAccountsWithoutAnyMfaMethods
                    + ", countOfUsersWithMfaMethodsMigrated="
                    + countOfUsersWithMfaMethodsMigrated
                    + ", countOfUsersWithoutMfaMethodsMigrated="
                    + countOfUsersWithoutMfaMethodsMigrated
                    + ", missingUserProfileCount="
                    + missingUserProfileCount
                    + ", mfaMethodPriorityIdentifierCombinations="
                    + getMfaMethodPriorityIdentifierCombinations()
                    + ", mfaMethodDetailsCombinations="
                    + mfaMethodDetailsCombinations
                    + '}';
        }
    }
}
