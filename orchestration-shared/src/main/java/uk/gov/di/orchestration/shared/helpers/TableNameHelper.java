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
        if (authDynamoArnPrefix.isPresent() && !isTableInOrchAccount) {
            return authDynamoArnPrefix.get() + tableName;
        }
        return configurationService.getEnvironment() + "-" + tableName;
    }
}
