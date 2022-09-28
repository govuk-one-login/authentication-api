package uk.gov.di.authentication.shared.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbIndex;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.TransactWriteItemsEnhancedRequest;
import uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.MFAMethod;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.Argon2EncoderHelper;
import uk.gov.di.authentication.shared.helpers.Argon2MatcherHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.PhoneNumberHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import static java.util.Objects.nonNull;

public class DynamoService implements AuthenticationService {

    private final DynamoDbTable<UserProfile> dynamoUserProfileTable;
    private final DynamoDbTable<UserCredentials> dynamoUserCredentialsTable;
    private final DynamoDbEnhancedClient dynamoDbEnhancedClient;
    private static final String USER_PROFILE_TABLE = "user-profile";
    private static final String USER_CREDENTIAL_TABLE = "user-credentials";

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
    public void signUp(
            String email, String password, Subject subject, TermsAndConditions termsAndConditions) {
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
                        .withCreated(dateTime)
                        .withUpdated(dateTime)
                        .withPublicSubjectID((new Subject()).toString())
                        .withTermsAndConditions(termsAndConditions)
                        .withLegacySubjectID(null);
        dynamoUserCredentialsTable.putItem(userCredentials);
        dynamoUserProfileTable.putItem(userProfile);
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
    public void updateConsent(String email, ClientConsent clientConsent) {
        dynamoUserProfileTable.updateItem(
                dynamoUserProfileTable
                        .getItem(
                                Key.builder()
                                        .partitionValue(email.toLowerCase(Locale.ROOT))
                                        .build())
                        .setClientConsent(clientConsent));
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
    public Optional<List<ClientConsent>> getUserConsents(String email) {
        return Optional.ofNullable(
                dynamoUserProfileTable
                        .getItem(
                                Key.builder()
                                        .partitionValue(email.toLowerCase(Locale.ROOT))
                                        .build())
                        .getClientConsent());
    }

    @Override
    public void updatePhoneNumberAndAccountVerifiedStatus(String email, boolean verifiedStatus) {
        var userProfile =
                dynamoUserProfileTable
                        .getItem(
                                Key.builder()
                                        .partitionValue(email.toLowerCase(Locale.ROOT))
                                        .build())
                        .withPhoneNumberVerified(verifiedStatus);
        if (verifiedStatus) userProfile.withAccountVerified(1);
        dynamoUserProfileTable.updateItem(userProfile);
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
    public void setMFAMethodVerifiedTrue(String email, MFAMethodType mfaMethodType) {
        var dateTime = NowHelper.toTimestampString(NowHelper.now());
        var userCredentials =
                dynamoUserCredentialsTable.getItem(
                        Key.builder().partitionValue(email.toLowerCase(Locale.ROOT)).build());
        var mfaMethod =
                userCredentials.getMfaMethods().stream()
                        .filter(
                                method ->
                                        method.getMfaMethodType().equals(mfaMethodType.getValue()))
                        .findFirst()
                        .orElseThrow();

        mfaMethod.withMethodVerified(true);
        mfaMethod.withUpdated(dateTime);
        dynamoUserCredentialsTable.updateItem(userCredentials);
    }

    @Override
    public UserProfile getUserProfileFromSubject(String subject) {
        QueryConditional q =
                QueryConditional.keyEqualTo(Key.builder().partitionValue(subject).build());
        DynamoDbIndex<UserProfile> subjectIDIndex = dynamoUserProfileTable.index("SubjectIDIndex");
        QueryEnhancedRequest queryEnhancedRequest =
                QueryEnhancedRequest.builder().consistentRead(false).queryConditional(q).build();
        Optional<UserProfile> userProfile =
                subjectIDIndex.query(queryEnhancedRequest).stream()
                        .limit(1)
                        .map(t -> t.items().get(0))
                        .findFirst();
        if (userProfile.isEmpty()) {
            throw new RuntimeException("No userCredentials found with query search");
        }
        return userProfile.get();
    }

    @Override
    public UserProfile getUserProfileFromPublicSubject(String subject) {
        QueryConditional q =
                QueryConditional.keyEqualTo(Key.builder().partitionValue(subject).build());
        DynamoDbIndex<UserProfile> subjectIDIndex =
                dynamoUserProfileTable.index("PublicSubjectIDIndex");
        QueryEnhancedRequest queryEnhancedRequest =
                QueryEnhancedRequest.builder().consistentRead(false).queryConditional(q).build();
        Optional<UserProfile> userProfile =
                subjectIDIndex.query(queryEnhancedRequest).stream()
                        .limit(1)
                        .map(t -> t.items().get(0))
                        .findFirst();
        if (userProfile.isEmpty()) {
            throw new RuntimeException("No userCredentials found with query search");
        }
        return userProfile.get();
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

    private static String hashPassword(String password) {
        return Argon2EncoderHelper.argon2Hash(password);
    }

    private void warmUp() {
        dynamoUserProfileTable.describeTable();
    }
}
