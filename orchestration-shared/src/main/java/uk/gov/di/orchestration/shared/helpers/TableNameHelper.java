package uk.gov.di.orchestration.shared.helpers;

import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.util.Optional;

public class TableNameHelper {

    private TableNameHelper() {}

    public static String getFullTableName(
            String tableName,
            ConfigurationService configurationService,
            boolean isTableInOrchAccount) {
        Optional<String> authDynamoArnPrefix = configurationService.getDynamoArnPrefix();
        Optional<String> orchDynamoArnPrefix = configurationService.getOrchDynamoArnPrefix();
        if (authDynamoArnPrefix.isPresent() && !isTableInOrchAccount) {
            return authDynamoArnPrefix.get() + tableName;
        } else if (orchDynamoArnPrefix.isPresent() && isTableInOrchAccount) {
            return orchDynamoArnPrefix.get() + tableName;
        }
        return configurationService.getEnvironment() + "-" + tableName;
    }
}
