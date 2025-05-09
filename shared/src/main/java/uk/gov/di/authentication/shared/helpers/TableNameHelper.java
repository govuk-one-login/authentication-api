package uk.gov.di.authentication.shared.helpers;

import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Optional;

public class TableNameHelper {

    private TableNameHelper() {}

    public static String getFullTableName(
            String tableName, ConfigurationService configurationService) {
        Optional<String> authDynamoArnPrefix = configurationService.getDynamoArnPrefix();
        if (authDynamoArnPrefix.isPresent()) {
            return authDynamoArnPrefix.get()
                    + configurationService.getEnvironment()
                    + "-"
                    + tableName;
        }
        return configurationService.getEnvironment() + "-" + tableName;
    }
}
