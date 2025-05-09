package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TableNameHelperTest {
    private static final String DYNAMO_ARN_PREFIX = "arn:aws:dynamodb:eu-west-2:12345:table/";
    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    @Test
    void shouldReturnTableFullArnIfPrefixDefined() {
        when(configurationService.getDynamoArnPrefix()).thenReturn(Optional.of(DYNAMO_ARN_PREFIX));
        when(configurationService.getEnvironment()).thenReturn("test");

        String fullTableName = TableNameHelper.getFullTableName("auth-table", configurationService);

        assertEquals(DYNAMO_ARN_PREFIX + "test-auth-table", fullTableName);
    }

    @Test
    void shouldReturnTableNameIfNoPrefixDefined() {
        when(configurationService.getEnvironment()).thenReturn("dev");

        String fullTableName =
                TableNameHelper.getFullTableName("local-table", configurationService);

        assertEquals("dev-local-table", fullTableName);
    }
}
