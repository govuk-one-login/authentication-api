package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import uk.gov.di.orchestration.shared.dynamodb.DynamoClientHelper;
import uk.gov.di.orchestration.shared.entity.UserCredentials;
import uk.gov.di.orchestration.shared.entity.UserProfile;

public class DynamoService {
    private final DynamoDbTable<UserProfile> dynamoUserProfileTable;
    private final DynamoDbEnhancedClient dynamoDbEnhancedClient;
    private static final String USER_PROFILE_TABLE = "user-profile";
    private static final Logger LOG = LogManager.getLogger(DynamoService.class);

    public DynamoService(
            DynamoDbTable<UserProfile> dynamoUserProfileTable,
            DynamoDbTable<UserCredentials> dynamoUserCredentialsTable,
            DynamoDbEnhancedClient dynamoDbEnhancedClient) {
        this.dynamoUserProfileTable = dynamoUserProfileTable;
        this.dynamoDbEnhancedClient = dynamoDbEnhancedClient;
    }

    public DynamoService(ConfigurationService configurationService) {
        String userProfileTableName = USER_PROFILE_TABLE;

        if (configurationService.getDynamoArnPrefix().isPresent()) {
            userProfileTableName =
                    configurationService.getDynamoArnPrefix().get() + userProfileTableName;
        } else {
            userProfileTableName =
                    configurationService.getEnvironment() + "-" + userProfileTableName;
        }

        dynamoDbEnhancedClient =
                DynamoClientHelper.createDynamoEnhancedClient(configurationService);
        this.dynamoUserProfileTable =
                dynamoDbEnhancedClient.table(
                        userProfileTableName, TableSchema.fromBean(UserProfile.class));
        warmUp();
    }

    private void warmUp() {
        dynamoUserProfileTable.describeTable();
    }
}
