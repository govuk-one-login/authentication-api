package uk.gov.di.authentication.accountdata.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.TransactWriteItemsEnhancedRequest;
import uk.gov.di.authentication.accountdata.entity.AuthenticatorItemKey;
import uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper;
import uk.gov.di.authentication.shared.entity.AccountModifiers;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.TableNameHelper;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.warmUp;

public class AccountDeleteDynamoService {

    private static final Logger LOG = LogManager.getLogger(AccountDeleteDynamoService.class);
    private static final int DYNAMO_TRANSACTION_LIMIT = 100;
    private static final int GUARANTEED_TRANSACTION_ITEMS = 2;

    private static final String USER_PROFILE_TABLE = "user-profile";
    private static final String USER_CREDENTIALS_TABLE = "user-credentials";
    private static final String ACCOUNT_MODIFIERS_TABLE = "account-modifiers";
    private static final String AUTHENTICATOR_TABLE = "authenticator";

    private final DynamoDbEnhancedClient dynamoDbEnhancedClient;
    private final DynamoDbTable<UserProfile> userProfileTable;
    private final DynamoDbTable<UserCredentials> userCredentialsTable;
    private final DynamoDbTable<AccountModifiers> accountModifiersTable;
    private final DynamoDbTable<AuthenticatorItemKey> authenticatorTable;

    public AccountDeleteDynamoService(ConfigurationService configurationService) {
        this.dynamoDbEnhancedClient =
                DynamoClientHelper.createDynamoEnhancedClient(configurationService);

        this.userProfileTable =
                dynamoDbEnhancedClient.table(
                        TableNameHelper.getFullTableName(USER_PROFILE_TABLE, configurationService),
                        TableSchema.fromBean(UserProfile.class));
        this.userCredentialsTable =
                dynamoDbEnhancedClient.table(
                        TableNameHelper.getFullTableName(
                                USER_CREDENTIALS_TABLE, configurationService),
                        TableSchema.fromBean(UserCredentials.class));
        this.accountModifiersTable =
                dynamoDbEnhancedClient.table(
                        TableNameHelper.getFullTableName(
                                ACCOUNT_MODIFIERS_TABLE, configurationService),
                        TableSchema.fromBean(AccountModifiers.class));
        this.authenticatorTable =
                dynamoDbEnhancedClient.table(
                        TableNameHelper.getFullTableName(AUTHENTICATOR_TABLE, configurationService),
                        TableSchema.fromBean(AuthenticatorItemKey.class));

        warmUp(userProfileTable);
        warmUp(userCredentialsTable);
        warmUp(accountModifiersTable);
        warmUp(authenticatorTable);
    }

    public AccountDeleteDynamoService(
            DynamoDbEnhancedClient dynamoDbEnhancedClient,
            DynamoDbTable<UserProfile> userProfileTable,
            DynamoDbTable<UserCredentials> userCredentialsTable,
            DynamoDbTable<AccountModifiers> accountModifiersTable,
            DynamoDbTable<AuthenticatorItemKey> authenticatorTable) {
        this.dynamoDbEnhancedClient = dynamoDbEnhancedClient;
        this.userProfileTable = userProfileTable;
        this.userCredentialsTable = userCredentialsTable;
        this.accountModifiersTable = accountModifiersTable;
        this.authenticatorTable = authenticatorTable;
    }

    public void deleteAccount(String email, String internalSubPairwiseId, String publicSubjectId) {
        var transactionBuilder =
                TransactWriteItemsEnhancedRequest.builder()
                        .addDeleteItem(
                                userCredentialsTable,
                                Key.builder()
                                        .partitionValue(email.toLowerCase(Locale.ROOT))
                                        .build())
                        .addDeleteItem(
                                userProfileTable,
                                Key.builder()
                                        .partitionValue(email.toLowerCase(Locale.ROOT))
                                        .build());

        var accountModifiers =
                Optional.ofNullable(
                        accountModifiersTable.getItem(
                                Key.builder().partitionValue(internalSubPairwiseId).build()));

        accountModifiers.ifPresent(
                item ->
                        transactionBuilder.addDeleteItem(
                                accountModifiersTable,
                                Key.builder()
                                        .partitionValue(item.getInternalCommonSubjectIdentifier())
                                        .build()));

        var authenticatorItems = getAuthenticatorItems(publicSubjectId);
        int transactionItemCount =
                GUARANTEED_TRANSACTION_ITEMS + (accountModifiers.isPresent() ? 1 : 0);
        int availableTransactionCapacity = DYNAMO_TRANSACTION_LIMIT - transactionItemCount;

        if (authenticatorItems.size() <= availableTransactionCapacity) {
            authenticatorItems.forEach(
                    item ->
                            transactionBuilder.addDeleteItem(
                                    authenticatorTable,
                                    Key.builder()
                                            .partitionValue(item.getPublicSubjectId())
                                            .sortValue(item.getSortKey())
                                            .build()));
        } else {
            LOG.warn(
                    "User has {} authenticator items which exceeds transaction capacity of {}. "
                            + "Deleting authenticator items prior to the main account "
                            + "deletion transaction.",
                    authenticatorItems.size(),
                    availableTransactionCapacity);
            deleteAuthenticatorItemsIndividually(authenticatorItems);
        }

        dynamoDbEnhancedClient.transactWriteItems(transactionBuilder.build());
    }

    private List<AuthenticatorItemKey> getAuthenticatorItems(String publicSubjectId) {
        var queryConditional =
                QueryConditional.keyEqualTo(Key.builder().partitionValue(publicSubjectId).build());
        return authenticatorTable
                .query(QueryEnhancedRequest.builder().queryConditional(queryConditional).build())
                .items()
                .stream()
                .toList();
    }

    private void deleteAuthenticatorItemsIndividually(List<AuthenticatorItemKey> items) {
        for (AuthenticatorItemKey item : items) {
            authenticatorTable.deleteItem(
                    Key.builder()
                            .partitionValue(item.getPublicSubjectId())
                            .sortValue(item.getSortKey())
                            .build());
        }
    }
}
