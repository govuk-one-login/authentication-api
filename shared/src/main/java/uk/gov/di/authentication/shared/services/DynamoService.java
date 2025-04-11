package uk.gov.di.authentication.shared.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbIndex;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Expression;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.ScanEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.TransactWriteItemsEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.User;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.Argon2EncoderHelper;
import uk.gov.di.authentication.shared.helpers.Argon2MatcherHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.PhoneNumberHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.lang.String.format;
import static java.util.Objects.nonNull;
import static software.amazon.awssdk.enhanced.dynamodb.internal.AttributeValues.numberValue;
import static software.amazon.awssdk.enhanced.dynamodb.internal.AttributeValues.stringValue;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.BACKUP;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.DEFAULT;

public class DynamoService implements AuthenticationService {
    private final DynamoDbTable<UserProfile> dynamoUserProfileTable;
    private final DynamoDbTable<UserCredentials> dynamoUserCredentialsTable;
    private final DynamoDbEnhancedClient dynamoDbEnhancedClient;
    private static final String USER_PROFILE_TABLE = "user-profile";
    private static final String USER_CREDENTIAL_TABLE = "user-credentials";
    private static final String TEST_USER_INDEX_NAME = "TestUserIndex";
    private static final Logger LOG = LogManager.getLogger(DynamoService.class);

    public DynamoService(ConfigurationService configurationService) {
        String userProfileTableName =
                configurationService.getEnvironment() + "-" + USER_PROFILE_TABLE;
        String userCredentialsTableName =
                configurationService.getEnvironment() + "-" + USER_CREDENTIAL_TABLE;
        dynamoDbEnhancedClient =
                DynamoClientHelper.createDynamoEnhancedClient(configurationService);
        this.dynamoUserProfileTable =
                dynamoDbEnhancedClient.table(
                        userProfileTableName, TableSchema.fromBean(UserProfile.class));
        this.dynamoUserCredentialsTable =
                dynamoDbEnhancedClient.table(
                        userCredentialsTableName, TableSchema.fromBean(UserCredentials.class));
        warmUp();
    }

    @Override
    public boolean userExists(String email) {
        return dynamoUserProfileTable.getItem(
                        Key.builder().partitionValue(email.toLowerCase(Locale.ROOT)).build())
                != null;
    }

    @Override
    public User signUp(
            String email, String password, Subject subject, TermsAndConditions termsAndConditions) {
        return signUp(email, password, subject, termsAndConditions, false, 0);
    }

    public User signUp(
            String email,
            String password,
            Subject subject,
            TermsAndConditions termsAndConditions,
            boolean isTestUser,
            int accountVerified) {
        var dateTime = LocalDateTime.now().toString();
        var hashedPassword = hashPassword(password);
        var userCredentials =
                new UserCredentials()
                        .withEmail(email.toLowerCase(Locale.ROOT))
                        .withSubjectID(subject.toString())
                        .withPassword(hashedPassword)
                        .withCreated(dateTime)
                        .withUpdated(dateTime);

        var userProfile =
                new UserProfile()
                        .withEmail(email.toLowerCase(Locale.ROOT))
                        .withSubjectID(subject.toString())
                        .withEmailVerified(true)
                        .withAccountVerified(accountVerified)
                        .withCreated(dateTime)
                        .withUpdated(dateTime)
                        .withPublicSubjectID((new Subject()).toString())
                        .withTermsAndConditions(termsAndConditions)
                        .withLegacySubjectID(null);
        userProfile.setSalt(SaltHelper.generateNewSalt());

        if (isTestUser) {
            userCredentials.setTestUser(1);
            userProfile.setTestUser(1);
        }

        dynamoUserCredentialsTable.putItem(userCredentials);
        dynamoUserProfileTable.putItem(userProfile);
        return new User(userProfile, userCredentials);
    }

    @Override
    public boolean login(String email, String password) {
        var userCredentials =
                dynamoUserCredentialsTable.getItem(
                        Key.builder().partitionValue(email.toLowerCase(Locale.ROOT)).build());
        return login(userCredentials, password);
    }

    @Override
    public boolean login(UserCredentials credentials, String password) {
        return Argon2MatcherHelper.matchRawStringWithEncoded(password, credentials.getPassword());
    }

    @Override
    public Subject getSubjectFromEmail(String email) {
        return new Subject(
                dynamoUserProfileTable
                        .getItem(
                                Key.builder()
                                        .partitionValue(email.toLowerCase(Locale.ROOT))
                                        .build())
                        .getSubjectID());
    }

    @Override
    public void updatePhoneNumber(String email, String phoneNumber) {
        var formattedPhoneNumber = PhoneNumberHelper.formatPhoneNumber(phoneNumber);
        dynamoUserProfileTable.updateItem(
                dynamoUserProfileTable
                        .getItem(
                                Key.builder()
                                        .partitionValue(email.toLowerCase(Locale.ROOT))
                                        .build())
                        .withPhoneNumber(formattedPhoneNumber));
    }

    @Override
    public UserProfile getUserProfileByEmail(String email) {
        return dynamoUserProfileTable.getItem(
                Key.builder().partitionValue(email.toLowerCase(Locale.ROOT)).build());
    }

    @Override
    public Optional<UserProfile> getUserProfileByEmailMaybe(String email) {
        return Optional.ofNullable(getUserProfileByEmail(email));
    }

    @Override
    public void updateTermsAndConditions(String email, String version) {
        var termsAndConditions =
                new TermsAndConditions(version, LocalDateTime.now(ZoneId.of("UTC")).toString());
        dynamoUserProfileTable.updateItem(
                dynamoUserProfileTable
                        .getItem(
                                Key.builder()
                                        .partitionValue(email.toLowerCase(Locale.ROOT))
                                        .build())
                        .withTermsAndConditions(termsAndConditions));
    }

    @Override
    public void updateEmail(String currentEmail, String newEmail) {
        updateEmail(currentEmail, newEmail, LocalDateTime.now(ZoneId.of("UTC")));
    }

    @Override
    public void updateEmail(String currentEmail, String newEmail, LocalDateTime updatedDateTime) {
        var userProfile =
                dynamoUserProfileTable
                        .getItem(
                                Key.builder()
                                        .partitionValue(currentEmail.toLowerCase(Locale.ROOT))
                                        .build())
                        .withEmail(newEmail.toLowerCase(Locale.ROOT))
                        .withUpdated(updatedDateTime.toString());
        var userCredentials =
                dynamoUserCredentialsTable
                        .getItem(
                                Key.builder()
                                        .partitionValue(currentEmail.toLowerCase(Locale.ROOT))
                                        .build())
                        .withEmail(newEmail.toLowerCase(Locale.ROOT))
                        .withUpdated(updatedDateTime.toString());

        dynamoDbEnhancedClient.transactWriteItems(
                TransactWriteItemsEnhancedRequest.builder()
                        .addPutItem(dynamoUserCredentialsTable, userCredentials)
                        .addPutItem(dynamoUserProfileTable, userProfile)
                        .addDeleteItem(
                                dynamoUserCredentialsTable,
                                Key.builder()
                                        .partitionValue(currentEmail.toLowerCase(Locale.ROOT))
                                        .build())
                        .addDeleteItem(
                                dynamoUserProfileTable,
                                Key.builder()
                                        .partitionValue(currentEmail.toLowerCase(Locale.ROOT))
                                        .build())
                        .build());
    }

    @Override
    public void updatePassword(String email, String newPassword) {
        dynamoUserCredentialsTable.updateItem(
                dynamoUserCredentialsTable
                        .getItem(
                                Key.builder()
                                        .partitionValue(email.toLowerCase(Locale.ROOT))
                                        .build())
                        .withPassword(hashPassword(newPassword))
                        .withMigratedPassword(null));
    }

    @Override
    public void removeAccount(String email) {
        dynamoDbEnhancedClient.transactWriteItems(
                TransactWriteItemsEnhancedRequest.builder()
                        .addDeleteItem(
                                dynamoUserCredentialsTable,
                                Key.builder()
                                        .partitionValue(email.toLowerCase(Locale.ROOT))
                                        .build())
                        .addDeleteItem(
                                dynamoUserProfileTable,
                                Key.builder()
                                        .partitionValue(email.toLowerCase(Locale.ROOT))
                                        .build())
                        .build());
    }

    @Override
    public UserCredentials getUserCredentialsFromSubject(String subject) {
        QueryConditional q =
                QueryConditional.keyEqualTo(Key.builder().partitionValue(subject).build());
        DynamoDbIndex<UserCredentials> subjectIDIndex =
                dynamoUserCredentialsTable.index("SubjectIDIndex");
        QueryEnhancedRequest queryEnhancedRequest =
                QueryEnhancedRequest.builder().consistentRead(false).queryConditional(q).build();
        Optional<UserCredentials> userCredentials =
                subjectIDIndex.query(queryEnhancedRequest).stream()
                        .limit(1)
                        .map(t -> t.items().get(0))
                        .findFirst();
        if (userCredentials.isEmpty()) {
            throw new RuntimeException("No userCredentials found with query search");
        }
        return userCredentials.get();
    }

    @Override
    public Optional<UserProfile> getUserProfileFromEmail(String email) {
        if (nonNull(email) && !email.isBlank()) {
            var userCredentials =
                    dynamoUserCredentialsTable.getItem(
                            Key.builder().partitionValue(email.toLowerCase(Locale.ROOT)).build());

            if (nonNull(userCredentials)) {
                return Optional.of(getUserProfileFromSubject(userCredentials.getSubjectID()));
            }
        }
        return Optional.empty();
    }

    @Override
    public UserCredentials getUserCredentialsFromEmail(String email) {
        return dynamoUserCredentialsTable.getItem(
                Key.builder().partitionValue(email.toLowerCase(Locale.ROOT)).build());
    }

    @Override
    public void migrateLegacyPassword(String email, String password) {
        dynamoUserCredentialsTable.updateItem(
                dynamoUserCredentialsTable
                        .getItem(
                                Key.builder()
                                        .partitionValue(email.toLowerCase(Locale.ROOT))
                                        .build())
                        .withPassword(hashPassword(password))
                        .withMigratedPassword(null));
    }

    @Override
    public byte[] getOrGenerateSalt(UserProfile userProfile) {
        if (userProfile.getSalt() == null
                || SdkBytes.fromByteBuffer(userProfile.getSalt()).asByteArray().length == 0) {
            byte[] salt = SaltHelper.generateNewSalt();
            userProfile.setSalt(salt);
            dynamoUserProfileTable.updateItem(
                    getUserProfileFromSubject(userProfile.getSubjectID())
                            .withSalt(userProfile.getSalt()));
        }
        return SdkBytes.fromByteBuffer(userProfile.getSalt()).asByteArray();
    }

    @Override
    public void updatePhoneNumberAndAccountVerifiedStatus(
            String email,
            String phoneNumber,
            boolean phoneNumberVerified,
            boolean accountVerified) {
        var dateTime = NowHelper.toTimestampString(NowHelper.now());
        var formattedPhoneNumber = PhoneNumberHelper.formatPhoneNumber(phoneNumber);
        var userProfile =
                dynamoUserProfileTable
                        .getItem(
                                Key.builder()
                                        .partitionValue(email.toLowerCase(Locale.ROOT))
                                        .build())
                        .withPhoneNumber(formattedPhoneNumber)
                        .withPhoneNumberVerified(phoneNumberVerified)
                        .withUpdated(dateTime)
                        .withAccountVerified(accountVerified ? 1 : 0);
        var userCredentials =
                dynamoUserCredentialsTable.getItem(
                        Key.builder().partitionValue(email.toLowerCase(Locale.ROOT)).build());

        var transactWriteBuilder =
                TransactWriteItemsEnhancedRequest.builder()
                        .addUpdateItem(dynamoUserProfileTable, userProfile);

        Optional.ofNullable(userCredentials.getMfaMethods())
                .flatMap(
                        mf ->
                                mf.stream()
                                        .filter(
                                                method ->
                                                        method.getMfaMethodType()
                                                                        .equals(
                                                                                MFAMethodType
                                                                                        .AUTH_APP
                                                                                        .getValue())
                                                                && method.isEnabled())
                                        .findFirst())
                .ifPresent(
                        t -> {
                            userCredentials
                                    .setMfaMethod(t.withEnabled(false).withUpdated(dateTime))
                                    .withUpdated(dateTime);
                            transactWriteBuilder.addUpdateItem(
                                    dynamoUserCredentialsTable, userCredentials);
                        });
        dynamoDbEnhancedClient.transactWriteItems(transactWriteBuilder.build());
    }

    @Override
    public void setVerifiedPhoneNumberAndRemoveAuthAppIfPresent(String email, String phoneNumber) {
        var dateTime = NowHelper.toTimestampString(NowHelper.now());
        var formattedPhoneNumber = PhoneNumberHelper.formatPhoneNumber(phoneNumber);
        var userProfile =
                dynamoUserProfileTable
                        .getItem(
                                Key.builder()
                                        .partitionValue(email.toLowerCase(Locale.ROOT))
                                        .build())
                        .withPhoneNumber(formattedPhoneNumber)
                        .withPhoneNumberVerified(true)
                        .withUpdated(dateTime);

        var userCredentials =
                dynamoUserCredentialsTable.getItem(
                        Key.builder().partitionValue(email.toLowerCase(Locale.ROOT)).build());

        var transactWriteBuilder =
                TransactWriteItemsEnhancedRequest.builder()
                        .addUpdateItem(dynamoUserProfileTable, userProfile);

        Optional.ofNullable(userCredentials.getMfaMethods())
                .flatMap(
                        mf ->
                                mf.stream()
                                        .filter(
                                                method ->
                                                        method.getMfaMethodType()
                                                                        .equals(
                                                                                MFAMethodType
                                                                                        .AUTH_APP
                                                                                        .getValue())
                                                                && method.isEnabled()
                                                                && method.isMethodVerified())
                                        .findFirst())
                .ifPresent(
                        t -> {
                            userCredentials
                                    .removeAuthAppByCredentialIfPresent(t.getCredentialValue())
                                    .withUpdated(dateTime);
                            transactWriteBuilder.addUpdateItem(
                                    dynamoUserCredentialsTable, userCredentials);
                        });
        dynamoDbEnhancedClient.transactWriteItems(transactWriteBuilder.build());
    }

    @Override
    public Optional<String> getPhoneNumber(String email) {
        return Optional.ofNullable(
                dynamoUserProfileTable
                        .getItem(
                                Key.builder()
                                        .partitionValue(email.toLowerCase(Locale.ROOT))
                                        .build())
                        .getPhoneNumber());
    }

    @Override
    public void updateMFAMethod(
            String email,
            MFAMethodType mfaMethodType,
            boolean methodVerified,
            boolean enabled,
            String credentialValue) {
        String dateTime = NowHelper.toTimestampString(NowHelper.now());
        MFAMethod mfaMethod =
                new MFAMethod(
                        MFAMethodType.AUTH_APP.getValue(),
                        credentialValue,
                        methodVerified,
                        enabled,
                        dateTime);
        dynamoUserCredentialsTable.updateItem(
                dynamoUserCredentialsTable
                        .getItem(
                                Key.builder()
                                        .partitionValue(email.toLowerCase(Locale.ROOT))
                                        .build())
                        .setMfaMethod(mfaMethod));
    }

    @Override
    public void addMFAMethodSupportingMultiple(String email, MFAMethod mfaMethod) {
        String dateTime = NowHelper.toTimestampString(NowHelper.now());
        mfaMethod.setUpdated(dateTime);

        dynamoUserCredentialsTable.updateItem(
                dynamoUserCredentialsTable
                        .getItem(
                                Key.builder()
                                        .partitionValue(email.toLowerCase(Locale.ROOT))
                                        .build())
                        .setMfaMethodBasedOnPriority(mfaMethod));
    }

    private UserCredentials overwriteUserCredentialsMfaMethods(
            String email, List<MFAMethod> mfaMethods) {
        String dateTime = NowHelper.toTimestampString(NowHelper.now());
        mfaMethods.forEach(mfaMethod -> mfaMethod.setUpdated(dateTime));

        return dynamoUserCredentialsTable
                .getItem(Key.builder().partitionValue(email.toLowerCase(Locale.ROOT)).build())
                .withMfaMethods(mfaMethods);
    }

    @Override
    public void setAuthAppAndAccountVerified(String email, String credentialValue) {
        var dateTime = NowHelper.toTimestampString(NowHelper.now());
        var mfaMethod =
                new MFAMethod(
                        MFAMethodType.AUTH_APP.getValue(), credentialValue, true, true, dateTime);
        var userCredentials =
                dynamoUserCredentialsTable
                        .getItem(
                                Key.builder()
                                        .partitionValue(email.toLowerCase(Locale.ROOT))
                                        .build())
                        .setMfaMethod(mfaMethod)
                        .withUpdated(dateTime);
        var userProfile =
                dynamoUserProfileTable
                        .getItem(
                                Key.builder()
                                        .partitionValue(email.toLowerCase(Locale.ROOT))
                                        .build())
                        .withAccountVerified(1)
                        .withUpdated(dateTime);

        dynamoDbEnhancedClient.transactWriteItems(
                TransactWriteItemsEnhancedRequest.builder()
                        .addUpdateItem(dynamoUserProfileTable, userProfile)
                        .addUpdateItem(dynamoUserCredentialsTable, userCredentials)
                        .build());
    }

    @Override
    public void setVerifiedAuthAppAndRemoveExistingMfaMethod(String email, String credentialValue) {
        var dateTime = NowHelper.toTimestampString(NowHelper.now());
        var mfaMethod =
                new MFAMethod(
                        MFAMethodType.AUTH_APP.getValue(), credentialValue, true, true, dateTime);
        var userCredentials =
                dynamoUserCredentialsTable
                        .getItem(
                                Key.builder()
                                        .partitionValue(email.toLowerCase(Locale.ROOT))
                                        .build())
                        .setMfaMethod(mfaMethod);

        var userProfile =
                dynamoUserProfileTable.getItem(
                        Key.builder().partitionValue(email.toLowerCase(Locale.ROOT)).build());
        userProfile.setPhoneNumber(null);
        userProfile.setPhoneNumberVerified(false);

        dynamoDbEnhancedClient.transactWriteItems(
                TransactWriteItemsEnhancedRequest.builder()
                        .addUpdateItem(dynamoUserCredentialsTable, userCredentials)
                        .addUpdateItem(dynamoUserProfileTable, userProfile)
                        .build());
    }

    @Override
    public UserProfile getUserProfileFromSubject(String subject) {
        Optional<UserProfile> userProfile = getOptionalUserProfileFromSubject(subject);
        if (userProfile.isEmpty()) {
            throw new RuntimeException("No userCredentials found with query search");
        }
        return userProfile.get();
    }

    public Optional<UserProfile> getOptionalUserProfileFromSubject(String subject) {
        QueryConditional q =
                QueryConditional.keyEqualTo(Key.builder().partitionValue(subject).build());
        QueryEnhancedRequest queryEnhancedRequest =
                QueryEnhancedRequest.builder().consistentRead(false).queryConditional(q).build();
        return dynamoUserProfileTable.index("SubjectIDIndex").query(queryEnhancedRequest).stream()
                .findFirst()
                .flatMap(page -> page.items().stream().findFirst());
    }

    @Override
    public Optional<UserProfile> getOptionalUserProfileFromPublicSubject(String subject) {
        QueryConditional q =
                QueryConditional.keyEqualTo(Key.builder().partitionValue(subject).build());
        DynamoDbIndex<UserProfile> subjectIDIndex =
                dynamoUserProfileTable.index("PublicSubjectIDIndex");
        QueryEnhancedRequest queryEnhancedRequest =
                QueryEnhancedRequest.builder().consistentRead(false).queryConditional(q).build();
        return subjectIDIndex.query(queryEnhancedRequest).stream()
                .findFirst()
                .flatMap(page -> page.items().stream().findFirst());
    }

    @Override
    public void setAccountVerified(String email) {
        dynamoUserProfileTable.updateItem(
                dynamoUserProfileTable
                        .getItem(
                                Key.builder()
                                        .partitionValue(email.toLowerCase(Locale.ROOT))
                                        .build())
                        .withAccountVerified(1));
    }

    @Override
    public void setMfaMethodsMigrated(String email, boolean mfaMethodsMigrated) {
        dynamoUserProfileTable.updateItem(buildSetMfaMethodsMigrated(email, mfaMethodsMigrated));
    }

    private UserProfile buildSetMfaMethodsMigrated(String email, boolean mfaMethodsMigrated) {
        return dynamoUserProfileTable
                .getItem(Key.builder().partitionValue(email.toLowerCase(Locale.ROOT)).build())
                .withMfaMethodsMigrated(mfaMethodsMigrated)
                .withPhoneNumber(null)
                .withPhoneNumberVerified(false)
                .withMfaIdentifier(null);
    }

    @Override
    public void overwriteMfaMethodToCredentialsAndDeleteProfilePhoneNumberForUser(
            String email, MFAMethod mfaMethod) {
        dynamoDbEnhancedClient.transactWriteItems(
                TransactWriteItemsEnhancedRequest.builder()
                        .addUpdateItem(
                                dynamoUserCredentialsTable,
                                overwriteUserCredentialsMfaMethods(email, List.of(mfaMethod)))
                        .addUpdateItem(
                                dynamoUserProfileTable, buildSetMfaMethodsMigrated(email, true))
                        .build());
    }

    public List<UserProfile> getAllBulkTestUsers() {
        Expression filterExpression =
                Expression.builder()
                        .expression("#testUser = :isTestUser")
                        .putExpressionName("#testUser", "testUser")
                        .putExpressionValue(":isTestUser", AttributeValue.fromN("1"))
                        .build();

        ScanEnhancedRequest scanRequest =
                ScanEnhancedRequest.builder().filterExpression(filterExpression).build();

        DynamoDbIndex<UserProfile> testUserIndex =
                dynamoUserProfileTable.index(TEST_USER_INDEX_NAME);

        var results = testUserIndex.scan(scanRequest);

        return results.stream()
                .flatMap(userProfilePage -> userProfilePage.items().stream())
                .collect(Collectors.toList());
    }

    public void createBatchTestUsers(Map<UserProfile, UserCredentials> testUsers) {
        int maxBatchWriteUsersToBothTables = 12;
        List<Map<UserProfile, UserCredentials>> partitions = new ArrayList<>();

        Iterator<Map.Entry<UserProfile, UserCredentials>> iterator =
                testUsers.entrySet().iterator();

        Map<UserProfile, UserCredentials> currentPartition = new HashMap<>();

        while (iterator.hasNext()) {
            Map.Entry<UserProfile, UserCredentials> entry = iterator.next();
            if (currentPartition.size() == maxBatchWriteUsersToBothTables) {
                partitions.add(currentPartition);
                currentPartition = new HashMap<>();
            }
            currentPartition.put(entry.getKey(), entry.getValue());
        }

        partitions.add(currentPartition);

        LOG.info(
                "Partitions: {} of max size {}", partitions.size(), maxBatchWriteUsersToBothTables);

        int numberOfThreadsForPartitionWrite = 4;
        int indexOfFinalPartition = partitions.size() - 1;
        int numberOfPartitionsPerThread =
                (int) Math.ceil((double) partitions.size() / numberOfThreadsForPartitionWrite);
        int indexOfFirstPartitionToBeProcessedByCurrentThread = 0;
        int indexOfLastPartitionToBeProcessedByCurrentThread = numberOfPartitionsPerThread - 1;

        List<Thread> dbWriterThreads = new ArrayList<>();

        while (indexOfFirstPartitionToBeProcessedByCurrentThread <= indexOfFinalPartition) {
            List<Map<UserProfile, UserCredentials>> partitionsForThisThread =
                    partitions.subList(
                            Math.min(
                                    indexOfFirstPartitionToBeProcessedByCurrentThread,
                                    indexOfFinalPartition),
                            Math.min(
                                    indexOfLastPartitionToBeProcessedByCurrentThread + 1,
                                    indexOfFinalPartition + 1));

            Runnable testUserDbWriter = new TestUserDbWriter(partitionsForThisThread);
            Thread dbWriterThread = new Thread(testUserDbWriter);
            dbWriterThreads.add(dbWriterThread);
            dbWriterThread.start();

            indexOfFirstPartitionToBeProcessedByCurrentThread += numberOfPartitionsPerThread;
            indexOfLastPartitionToBeProcessedByCurrentThread += numberOfPartitionsPerThread;
        }

        for (Thread thread : dbWriterThreads) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                LOG.error("Thread failed to write to DB");
                Thread.currentThread().interrupt();
            }
        }
    }

    private class TestUserDbWriter implements Runnable {
        private final List<Map<UserProfile, UserCredentials>> partitionsToWrite;

        public TestUserDbWriter(List<Map<UserProfile, UserCredentials>> partitionsToWrite) {
            this.partitionsToWrite = partitionsToWrite;
        }

        @Override
        public void run() {
            writeTestUserBatchPartitionToDb(partitionsToWrite);
        }

        private void writeTestUserBatchPartitionToDb(
                List<Map<UserProfile, UserCredentials>> testUserBatchPartitions) {
            for (Map<UserProfile, UserCredentials> testUserBatch : testUserBatchPartitions) {
                TransactWriteItemsEnhancedRequest.Builder insertItemsRequestBuilder =
                        TransactWriteItemsEnhancedRequest.builder();

                testUserBatch.forEach(
                        (key, value) ->
                                insertItemsRequestBuilder
                                        .addPutItem(dynamoUserProfileTable, key)
                                        .addPutItem(dynamoUserCredentialsTable, value));

                var insertItemsBatchRequest = insertItemsRequestBuilder.build();

                dynamoDbEnhancedClient.transactWriteItems(insertItemsBatchRequest);
            }
        }
    }

    public void deleteBatchTestUsers(List<String> emailAddresses) {
        int maxBatchWriteItemsToBothTables = 12;
        List<List<String>> partitions = new ArrayList<>();

        for (int i = 0; i < emailAddresses.size(); i += maxBatchWriteItemsToBothTables) {
            partitions.add(
                    emailAddresses.subList(
                            i,
                            Math.min(i + maxBatchWriteItemsToBothTables, emailAddresses.size())));
        }

        for (List<String> testUserBatch : partitions) {
            TransactWriteItemsEnhancedRequest.Builder deleteItemsRequestBuilder =
                    TransactWriteItemsEnhancedRequest.builder();

            testUserBatch.forEach(
                    emailAddress ->
                            deleteItemsRequestBuilder
                                    .addDeleteItem(
                                            dynamoUserCredentialsTable,
                                            Key.builder()
                                                    .partitionValue(
                                                            emailAddress.toLowerCase(Locale.ROOT))
                                                    .build())
                                    .addDeleteItem(
                                            dynamoUserProfileTable,
                                            Key.builder()
                                                    .partitionValue(
                                                            emailAddress.toLowerCase(Locale.ROOT))
                                                    .build()));

            var deleteItemsBatchRequest = deleteItemsRequestBuilder.build();

            dynamoDbEnhancedClient.transactWriteItems(deleteItemsBatchRequest);
        }
    }

    public void deleteMfaMethodByIdentifier(String email, String mfaMethodIdentifier) {
        var dateTime = NowHelper.toTimestampString(NowHelper.now());
        dynamoUserCredentialsTable.updateItem(
                dynamoUserCredentialsTable
                        .getItem(
                                Key.builder()
                                        .partitionValue(email.toLowerCase(Locale.ROOT))
                                        .build())
                        .removeMfaMethodByIdentifierIfPresent(mfaMethodIdentifier)
                        .withUpdated(dateTime));
    }

    @Override
    public Result<String, List<MFAMethod>> updateMigratedMethodPhoneNumber(
            String email, String updatedPhoneNumber, String mfaMethodIdentifier) {
        var userCredentials =
                dynamoUserCredentialsTable.getItem(
                        Key.builder().partitionValue(email.toLowerCase(Locale.ROOT)).build());
        var maybeExistingMethod = getMfaMethodByIdentifier(userCredentials, mfaMethodIdentifier);
        return maybeExistingMethod.flatMap(
                existingMethod -> {
                    if (!existingMethod.getMfaMethodType().equals(MFAMethodType.SMS.getValue())) {
                        return Result.failure(
                                format(
                                        "Attempted to update phone number for non sms method with identifier %s",
                                        mfaMethodIdentifier));
                    }
                    return Result.success(
                            updateMigratedMfaMethod(
                                    existingMethod.withDestination(updatedPhoneNumber),
                                    mfaMethodIdentifier,
                                    userCredentials));
                });
    }

    private List<MFAMethod> updateMigratedMfaMethod(
            MFAMethod updatedMFAMethod,
            String mfaMethodIdentifier,
            UserCredentials userCredentials) {
        var dateTime = NowHelper.toTimestampString(NowHelper.now());
        var updatedUserCredentials =
                dynamoUserCredentialsTable.updateItem(
                        userCredentials
                                .withUpdated(dateTime)
                                .withUpdatedMfaMethod(mfaMethodIdentifier, updatedMFAMethod));

        return updatedUserCredentials.getMfaMethods();
    }

    private Result<String, MFAMethod> getMfaMethodByIdentifier(
            UserCredentials userCredentials, String mfaMethodIdentifier) {
        var maybeExistingMethod =
                userCredentials.getMfaMethods().stream()
                        .filter(
                                mfaMethod ->
                                        mfaMethod.getMfaIdentifier().equals(mfaMethodIdentifier))
                        .findFirst();
        return maybeExistingMethod
                .<Result<String, MFAMethod>>map(Result::success)
                .orElseGet(
                        () ->
                                Result.failure(
                                        format(
                                                "Mfa method with identifier %s does not exist",
                                                mfaMethodIdentifier)));
    }

    @Override
    public Result<String, List<MFAMethod>> updateMigratedAuthAppCredential(
            String email, String updatedCredential, String mfaMethodIdentifier) {
        var userCredentials =
                dynamoUserCredentialsTable.getItem(
                        Key.builder().partitionValue(email.toLowerCase(Locale.ROOT)).build());
        var maybeExistingMethod = getMfaMethodByIdentifier(userCredentials, mfaMethodIdentifier);
        return maybeExistingMethod.flatMap(
                existingMethod -> {
                    if (!existingMethod
                            .getMfaMethodType()
                            .equals(MFAMethodType.AUTH_APP.getValue())) {
                        return Result.failure(
                                format(
                                        "Attempted to update auth app credential for non auth app method with identifier %s",
                                        mfaMethodIdentifier));
                    }
                    return Result.success(
                            updateMigratedMfaMethod(
                                    existingMethod.withCredentialValue(updatedCredential),
                                    mfaMethodIdentifier,
                                    userCredentials));
                });
    }

    private Result<String, Void> validateMfaMethods(List<MFAMethod> methods) {
        if (methods.isEmpty()) {
            return Result.failure("Mfa methods cannot be empty");
        } else if (methods.size() > 2) {
            return Result.failure("Cannot have more than two mfa methods");
        } else if (methods.stream()
                        .filter(
                                m ->
                                        Objects.equals(
                                                m.getMfaMethodType(),
                                                MFAMethodType.AUTH_APP.name()))
                        .toList()
                        .size()
                > 1) {
            return Result.failure("Cannot have two auth app mfa methods");
        }
        var backupMethods =
                methods.stream().filter(m -> BACKUP.name().equals(m.getPriority())).toList();
        var defaultMethods =
                methods.stream().filter(m -> DEFAULT.name().equals(m.getPriority())).toList();
        if (defaultMethods.size() > 1 || backupMethods.size() > 1) {
            return Result.failure("Cannot have two mfa methods with the same priority");
        }
        if (defaultMethods.isEmpty()) {
            return Result.failure("Must have default priority mfa method defined");
        }
        var uniqueIdentifiers =
                methods.stream().map(MFAMethod::getMfaIdentifier).collect(Collectors.toSet());
        if (uniqueIdentifiers.size() < methods.size()) {
            return Result.failure("Cannot have mfa methods with the same identifier");
        }

        return Result.success(null);
    }

    @Override
    public Result<String, List<MFAMethod>> updateAllMfaMethodsForUser(
            String email, List<MFAMethod> updatedMfaMethods) {
        var validationResult = validateMfaMethods(updatedMfaMethods);

        return validationResult.map(
                success -> {
                    var userCredentials =
                            dynamoUserCredentialsTable.getItem(
                                    Key.builder()
                                            .partitionValue(email.toLowerCase(Locale.ROOT))
                                            .build());
                    var dateTime = NowHelper.toTimestampString(NowHelper.now());
                    var updatedUserCredentials =
                            dynamoUserCredentialsTable.updateItem(
                                    userCredentials
                                            .withUpdated(dateTime)
                                            .withMfaMethods(updatedMfaMethods));

                    return updatedUserCredentials.getMfaMethods();
                });
    }

    @Override
    public Result<String, Void> setMfaIdentifierForNonMigratedUserEnabledAuthApp(
            String email, String mfaMethodIdentifier) {
        var userCredentials =
                dynamoUserCredentialsTable.getItem(
                        Key.builder().partitionValue(email.toLowerCase(Locale.ROOT)).build());
        var dateTime = NowHelper.toTimestampString(NowHelper.now());
        var method =
                Optional.ofNullable(userCredentials.getMfaMethods())
                        .flatMap(
                                mfaMethods ->
                                        mfaMethods.stream()
                                                .filter(MFAMethod::isEnabled)
                                                .findFirst());
        if (method.isPresent()) {
            dynamoUserCredentialsTable
                    .updateItem(
                            dynamoUserCredentialsTable
                                    .getItem(
                                            Key.builder()
                                                    .partitionValue(email.toLowerCase(Locale.ROOT))
                                                    .build())
                                    .setMfaMethod(
                                            method.get().withMfaIdentifier(mfaMethodIdentifier)))
                    .withUpdated(dateTime);
            return Result.success(null);
        } else {
            return Result.failure(
                    "Attempted to set mfa identifier for mfa method in user credentials but no enabled method found");
        }
    }

    public void setMfaIdentifierForNonMigratedSmsMethod(String email, String smsMethodIdentifier) {
        var dateTime = NowHelper.toTimestampString(NowHelper.now());
        dynamoUserProfileTable
                .updateItem(
                        dynamoUserProfileTable
                                .getItem(
                                        Key.builder()
                                                .partitionValue(email.toLowerCase(Locale.ROOT))
                                                .build())
                                .withMfaIdentifier(smsMethodIdentifier))
                .withUpdated(dateTime);
    }

    public Stream<UserProfile> getBulkUserEmailAudienceStreamOnTermsAndConditionsVersion(
            Map<String, AttributeValue> exclusiveStartKey, List<String> termsAndConditionsVersion) {

        List<String> termsAndConditionsExpression = new ArrayList<>();
        List<String> expression = new ArrayList<>();
        Map<String, AttributeValue> expressionValues = new HashMap<>();

        for (int i = 0; i < termsAndConditionsVersion.size(); i++) {
            termsAndConditionsExpression.add(
                    format("termsAndConditions.version = :tc_version%d", i));
            expressionValues.put(
                    format(":tc_version%d", i), stringValue(termsAndConditionsVersion.get(i)));
        }
        String termsAndConditionsExpressionString =
                format(
                        " ( %s ) ",
                        termsAndConditionsExpression.stream().collect(Collectors.joining(" OR ")));

        expression.add(termsAndConditionsExpressionString);
        expression.add("attribute_exists(termsAndConditions.version)");
        expression.add("accountVerified = :accountVerified");
        expressionValues.put(":accountVerified", numberValue(1));

        String expressionString = expression.stream().collect(Collectors.joining(" AND "));

        ScanEnhancedRequest scanRequest =
                ScanEnhancedRequest.builder()
                        .addAttributeToProject("SubjectID")
                        .addAttributeToProject("Email")
                        .exclusiveStartKey(exclusiveStartKey)
                        .filterExpression(
                                Expression.builder()
                                        .expression(expressionString)
                                        .expressionValues(expressionValues)
                                        .build())
                        .build();
        return dynamoUserProfileTable.scan(scanRequest).items().stream();
    }

    private static String hashPassword(String password) {
        return Argon2EncoderHelper.argon2Hash(password);
    }

    private void warmUp() {
        dynamoUserProfileTable.describeTable();
    }
}
