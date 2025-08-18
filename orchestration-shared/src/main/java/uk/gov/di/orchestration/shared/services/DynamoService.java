package uk.gov.di.orchestration.shared.services;

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
import uk.gov.di.orchestration.shared.dynamodb.DynamoClientHelper;
import uk.gov.di.orchestration.shared.entity.UserCredentials;
import uk.gov.di.orchestration.shared.entity.UserProfile;
import uk.gov.di.orchestration.shared.helpers.SaltHelper;

import java.util.Locale;
import java.util.Optional;

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

    private void warmUp() {
        dynamoUserProfileTable.describeTable();
    }
}
