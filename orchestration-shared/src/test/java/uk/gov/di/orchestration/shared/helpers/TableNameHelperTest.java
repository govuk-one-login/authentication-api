package uk.gov.di.orchestration.shared.helpers;

import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

// QualityGateUnitTest
class TableNameHelperTest {
    private static final String TEST_AUTH_DYNAMO_ARN_PREFIX =
            "arn:aws:dynamodb:eu-west-2:12345:table/test-";
    private static final String TEST_ORCH_DYNAMO_ARN_PREFIX =
            "arn:aws:dynamodb:eu-west-2:56789:table/test-";
    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    // QualityGateRegressionTest
    @Test
    void shouldReturnTableArnForAuthTableWhenCalledInOrchAccount() {
        when(configurationService.getDynamoArnPrefix())
                .thenReturn(Optional.of(TEST_AUTH_DYNAMO_ARN_PREFIX));

        String fullTableName =
                TableNameHelper.getFullTableName("auth-table", configurationService, false);

        assertEquals(TEST_AUTH_DYNAMO_ARN_PREFIX + "auth-table", fullTableName);
    }

    // QualityGateRegressionTest
    @Test
    void shouldReturnTableArnForOrchTableWhenCalledInAuthAccount() {
        when(configurationService.getOrchDynamoArnPrefix())
                .thenReturn(Optional.of(TEST_ORCH_DYNAMO_ARN_PREFIX));

        String fullTableName =
                TableNameHelper.getFullTableName("orch-table", configurationService, true);

        assertEquals(TEST_ORCH_DYNAMO_ARN_PREFIX + "orch-table", fullTableName);
    }

    // QualityGateRegressionTest
    @Test
    void shouldReturnTableNameIfNoPrefixDefined() {
        when(configurationService.getEnvironment()).thenReturn("dev");

        String fullTableName =
                TableNameHelper.getFullTableName("local-table", configurationService, false);

        assertEquals("dev-local-table", fullTableName);
    }
}
