package uk.gov.di.orchestration.shared.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbIndex;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.TransactWriteItemsEnhancedRequest;
import uk.gov.di.orchestration.shared.dynamodb.DynamoClientHelper;
import uk.gov.di.orchestration.shared.entity.MFAMethodType;
import uk.gov.di.orchestration.shared.entity.TermsAndConditions;
import uk.gov.di.orchestration.shared.entity.User;
import uk.gov.di.orchestration.shared.entity.UserCredentials;
import uk.gov.di.orchestration.shared.entity.UserProfile;
import uk.gov.di.orchestration.shared.helpers.Argon2EncoderHelper;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.helpers.PhoneNumberHelper;
import uk.gov.di.orchestration.shared.helpers.SaltHelper;

import java.time.LocalDateTime;
import java.util.Locale;
import java.util.Optional;

import static java.util.Objects.nonNull;

public class DynamoService implements AuthenticationService {
    private final DynamoDbTable<UserProfile> dynamoUserProfileTable;
    private final DynamoDbTable<UserCredentials> dynamoUserCredentialsTable;
    private final DynamoDbEnhancedClient dynamoDbEnhancedClient;
    private static final String USER_PROFILE_TABLE = "user-profile";
    private static final String USER_CREDENTIAL_TABLE = "user-credentials";
    private static final Logger LOG = LogManager.getLogger(DynamoService.class);

    public DynamoService(
            DynamoDbTable<UserProfile> dynamoUserProfileTable,
            DynamoDbTable<UserCredentials> dynamoUserCredentialsTable,
            DynamoDbEnhancedClient dynamoDbEnhancedClient) {
        this.dynamoUserProfileTable = dynamoUserProfileTable;
        this.dynamoUserCredentialsTable = dynamoUserCredentialsTable;
        this.dynamoDbEnhancedClient = dynamoDbEnhancedClient;
    }

    public DynamoService(ConfigurationService configurationService) {
        String userProfileTableName = USER_PROFILE_TABLE;
        String userCredentialsTableName = USER_CREDENTIAL_TABLE;

        if (configurationService.getDynamoArnPrefix().isPresent()) {
            userProfileTableName =
                    configurationService.getDynamoArnPrefix().get() + userProfileTableName;
            userCredentialsTableName =
                    configurationService.getDynamoArnPrefix().get() + userCredentialsTableName;
        } else {
            userProfileTableName =
                    configurationService.getEnvironment() + "-" + userProfileTableName;
            userCredentialsTableName =
                    configurationService.getEnvironment() + "-" + userCredentialsTableName;
        }

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
    public UserProfile getUserProfileByEmail(String email) {
        if (email != null) {
            return dynamoUserProfileTable.getItem(
                    Key.builder().partitionValue(email.toLowerCase(Locale.ROOT)).build());
        } else {
            LOG.warn("Cannot get user profile as email is null");
            return null;
        }
    }

    @Override
    public Optional<UserProfile> getUserProfileByEmailMaybe(String email) {
        return Optional.ofNullable(getUserProfileByEmail(email));
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

    private UserProfile getUserProfileFromSubject(String subject) {
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

    private static String hashPassword(String password) {
        return Argon2EncoderHelper.argon2Hash(password);
    }

    private void warmUp() {
        dynamoUserProfileTable.describeTable();
    }
}
