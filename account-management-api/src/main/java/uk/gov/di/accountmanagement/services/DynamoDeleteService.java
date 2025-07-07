package uk.gov.di.accountmanagement.services;

import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.TransactWriteItemsEnhancedRequest;
import uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper;
import uk.gov.di.authentication.shared.entity.AccountModifiers;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Locale;
import java.util.Optional;

import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.warmUp;

public class DynamoDeleteService {

    private static final String USER_PROFILE_TABLE = "user-profile";
    private static final String USER_CREDENTIAL_TABLE = "user-credentials";
    private static final String ACCOUNT_MODIFIERS_TABLE_NAME = "account-modifiers";
    private final DynamoDbTable<AccountModifiers> dynamoAccountModifiersTable;
    private final DynamoDbTable<UserProfile> dynamoUserProfileTable;
    private final DynamoDbTable<UserCredentials> dynamoUserCredentialsTable;
    private final DynamoDbEnhancedClient dynamoDbEnhancedClient;

    public DynamoDeleteService(ConfigurationService configurationService) {
        var userProfileTableName = configurationService.getEnvironment() + "-" + USER_PROFILE_TABLE;
        var userCredentialsTableName =
                configurationService.getEnvironment() + "-" + USER_CREDENTIAL_TABLE;
        var accountModifiersTableName =
                configurationService.getEnvironment() + "-" + ACCOUNT_MODIFIERS_TABLE_NAME;

        this.dynamoDbEnhancedClient =
                DynamoClientHelper.createDynamoEnhancedClient(configurationService);
        this.dynamoUserProfileTable =
                dynamoDbEnhancedClient.table(
                        userProfileTableName, TableSchema.fromBean(UserProfile.class));
        this.dynamoUserCredentialsTable =
                dynamoDbEnhancedClient.table(
                        userCredentialsTableName, TableSchema.fromBean(UserCredentials.class));
        this.dynamoAccountModifiersTable =
                dynamoDbEnhancedClient.table(
                        accountModifiersTableName, TableSchema.fromBean(AccountModifiers.class));

        warmUp(dynamoUserProfileTable);
        warmUp(dynamoUserCredentialsTable);
        warmUp(dynamoAccountModifiersTable);
    }

    public void deleteAccount(String email, String internalSubPairwiseId) {
        var transactionWriterBuilder =
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
                                        .build());

        Optional.ofNullable(
                        dynamoAccountModifiersTable.getItem(
                                Key.builder().partitionValue(internalSubPairwiseId).build()))
                .ifPresent(
                        t ->
                                transactionWriterBuilder.addDeleteItem(
                                        dynamoAccountModifiersTable, t));

        dynamoDbEnhancedClient.transactWriteItems(transactionWriterBuilder.build());
    }
}
