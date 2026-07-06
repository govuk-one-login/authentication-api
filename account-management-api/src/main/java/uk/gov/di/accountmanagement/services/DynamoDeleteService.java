package uk.gov.di.accountmanagement.services;

import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.TransactWriteItemsEnhancedRequest;
import uk.gov.di.accountmanagement.entity.AuthenticatorItemKey;
import uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper;
import uk.gov.di.authentication.shared.entity.AccountModifiers;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.TableNameHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.warmUp;

public class DynamoDeleteService {

    private static final String USER_PROFILE_TABLE = "user-profile";
    private static final String USER_CREDENTIAL_TABLE = "user-credentials";
    private static final String ACCOUNT_MODIFIERS_TABLE_NAME = "account-modifiers";
    private static final String AUTHENTICATOR_TABLE = "authenticator";
    private final DynamoDbTable<AccountModifiers> dynamoAccountModifiersTable;
    private final DynamoDbTable<UserProfile> dynamoUserProfileTable;
    private final DynamoDbTable<UserCredentials> dynamoUserCredentialsTable;
    private final DynamoDbTable<AuthenticatorItemKey> dynamoAuthenticatorTable;
    private final DynamoDbEnhancedClient dynamoDbEnhancedClient;

    public DynamoDeleteService(ConfigurationService configurationService) {
        var userProfileTableName =
                TableNameHelper.getFullTableName(USER_PROFILE_TABLE, configurationService);
        var userCredentialsTableName =
                TableNameHelper.getFullTableName(USER_CREDENTIAL_TABLE, configurationService);
        var accountModifiersTableName =
                TableNameHelper.getFullTableName(
                        ACCOUNT_MODIFIERS_TABLE_NAME, configurationService);
        var authenticatorTableName =
                TableNameHelper.getFullTableName(AUTHENTICATOR_TABLE, configurationService);

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
        this.dynamoAuthenticatorTable =
                dynamoDbEnhancedClient.table(
                        authenticatorTableName, TableSchema.fromBean(AuthenticatorItemKey.class));

        warmUp(dynamoUserProfileTable);
        warmUp(dynamoUserCredentialsTable);
        warmUp(dynamoAccountModifiersTable);
        warmUp(dynamoAuthenticatorTable);
    }

    public void deleteAccount(String email, String internalSubPairwiseId, String publicSubjectId) {
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

        getAuthenticatorItems(publicSubjectId)
                .forEach(
                        item ->
                                transactionWriterBuilder.addDeleteItem(
                                        dynamoAuthenticatorTable,
                                        Key.builder()
                                                .partitionValue(item.getPublicSubjectId())
                                                .sortValue(item.getSortKey())
                                                .build()));

        dynamoDbEnhancedClient.transactWriteItems(transactionWriterBuilder.build());
    }

    private List<AuthenticatorItemKey> getAuthenticatorItems(String publicSubjectId) {
        var queryConditional =
                QueryConditional.keyEqualTo(Key.builder().partitionValue(publicSubjectId).build());
        return dynamoAuthenticatorTable
                .query(QueryEnhancedRequest.builder().queryConditional(queryConditional).build())
                .items()
                .stream()
                .toList();
    }
}
