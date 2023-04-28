package uk.gov.di.authentication.frontendapi.services;

import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import uk.gov.di.authentication.frontendapi.entity.AccountModifiers;
import uk.gov.di.authentication.frontendapi.entity.AccountRecovery;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoEnhancedClient;

public class DynamoAccountModifiersService {

    private static final String ACCOUNT_MODIFIERS_TABLE_NAME = "account-modifiers";
    private final DynamoDbTable<AccountModifiers> dynamoAccountModifiersTable;

    public DynamoAccountModifiersService(ConfigurationService configurationService) {
        var tableName = configurationService.getEnvironment() + "-" + ACCOUNT_MODIFIERS_TABLE_NAME;
        var dynamoDbEnhancedClient = createDynamoEnhancedClient(configurationService);
        dynamoAccountModifiersTable =
                dynamoDbEnhancedClient.table(
                        tableName, TableSchema.fromBean(AccountModifiers.class));
        warmUp();
    }

    public void setAccountRecoveryBlock(
            String internalCommonSubjectId, boolean accountRecoveryBlock) {
        var dateTime = NowHelper.toTimestampString(NowHelper.now());

        var optionalAccountModifiers =
                getAccountModifiers(internalCommonSubjectId)
                        .map(t -> t.withUpdated(dateTime))
                        .map(
                                t ->
                                        Objects.nonNull(t.getAccountRecovery())
                                                ? t.withAccountRecovery(
                                                        t.getAccountRecovery()
                                                                .withBlocked(true)
                                                                .withUpdated(dateTime))
                                                : t.withAccountRecovery(
                                                        new AccountRecovery()
                                                                .withCreated(dateTime)
                                                                .withUpdated(dateTime)
                                                                .withBlocked(true)));

        var accountModifiers =
                optionalAccountModifiers.orElse(
                        new AccountModifiers()
                                .withInternalCommonSubjectIdentifier(internalCommonSubjectId)
                                .withCreated(dateTime)
                                .withUpdated(dateTime)
                                .withAccountRecovery(
                                        new AccountRecovery()
                                                .withBlocked(accountRecoveryBlock)
                                                .withUpdated(dateTime)
                                                .withCreated(dateTime)));

        dynamoAccountModifiersTable.updateItem(accountModifiers);
    }

    public void removeAccountModifiersIfPresent(String internalCommonSubjectId) {
        if (getAccountModifiers(internalCommonSubjectId).isPresent()) {
            dynamoAccountModifiersTable.deleteItem(
                    Key.builder().partitionValue(internalCommonSubjectId).build());
        }
    }

    public Optional<AccountModifiers> getAccountModifiers(String internalCommonSubjectId) {
        return Optional.ofNullable(
                dynamoAccountModifiersTable.getItem(
                        Key.builder().partitionValue(internalCommonSubjectId).build()));
    }

    private void warmUp() {
        dynamoAccountModifiersTable.describeTable();
    }
}
