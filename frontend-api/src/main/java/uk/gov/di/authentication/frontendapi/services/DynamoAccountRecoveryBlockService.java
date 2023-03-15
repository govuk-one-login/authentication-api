package uk.gov.di.authentication.frontendapi.services;

import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.GetItemEnhancedRequest;
import uk.gov.di.authentication.frontendapi.entity.AccountRecoveryBlock;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.time.temporal.ChronoUnit;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoEnhancedClient;

public class DynamoAccountRecoveryBlockService {

    private static final String ACCOUNT_RECOVERY_BLOCK_TABLE = "account-recovery-block";
    private final long timeToExist;
    private final DynamoDbTable<AccountRecoveryBlock> dynamoAccountRecoveryBlockTable;

    public DynamoAccountRecoveryBlockService(ConfigurationService configurationService) {
        var tableName = configurationService.getEnvironment() + "-" + ACCOUNT_RECOVERY_BLOCK_TABLE;
        var dynamoDbEnhancedClient = createDynamoEnhancedClient(configurationService);
        timeToExist = configurationService.getAccountRecoveryBlockTTL();
        dynamoAccountRecoveryBlockTable =
                dynamoDbEnhancedClient.table(
                        tableName, TableSchema.fromBean(AccountRecoveryBlock.class));
        warmUp();
    }

    public void addBlockWithTTL(String email) {
        var accountRecoveryBlock =
                new AccountRecoveryBlock()
                        .withEmail(email)
                        .withTimeToExist(
                                NowHelper.nowPlus(timeToExist, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond());
        dynamoAccountRecoveryBlockTable.putItem(accountRecoveryBlock);
    }

    public void addBlockWithNoTTL(String email) {
        var accountRecoveryBlock = new AccountRecoveryBlock().withEmail(email);
        dynamoAccountRecoveryBlockTable.putItem(accountRecoveryBlock);
    }

    public boolean blockIsPresent(String email) {
        var getItemEnhancedRequest =
                GetItemEnhancedRequest.builder()
                        .consistentRead(true)
                        .key(k -> k.partitionValue(email))
                        .build();
        var blockedItem =
                Optional.ofNullable(
                        dynamoAccountRecoveryBlockTable.getItem(getItemEnhancedRequest));

        return blockedItem
                .filter(
                        t ->
                                Objects.isNull(t.getTimeToExist())
                                        || t.getTimeToExist()
                                                > NowHelper.now().toInstant().getEpochSecond())
                .isPresent();
    }

    private void warmUp() {
        dynamoAccountRecoveryBlockTable.describeTable();
    }
}
