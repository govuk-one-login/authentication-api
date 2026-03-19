package uk.gov.di.authentication.utils.services.audienceloader;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.utils.domain.DynamoTable;
import uk.gov.di.authentication.utils.exceptions.IncludedTermsAndConditionsConfigMissingException;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TermsAndConditionsBulkEmailAudienceLoaderTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final TermsAndConditionsBulkEmailAudienceLoader loader =
            new TermsAndConditionsBulkEmailAudienceLoader(configurationService, dynamoService);

    @Test
    void validateConfigShouldThrowWhenIncludedTermsAndConditionsIsNull() {
        when(configurationService.getBulkUserEmailIncludedTermsAndConditions()).thenReturn(null);

        assertThrows(
                IncludedTermsAndConditionsConfigMissingException.class, loader::validateConfig);
    }

    @Test
    void validateConfigShouldThrowWhenIncludedTermsAndConditionsIsEmpty() {
        when(configurationService.getBulkUserEmailIncludedTermsAndConditions())
                .thenReturn(List.of());

        assertThrows(
                IncludedTermsAndConditionsConfigMissingException.class, loader::validateConfig);
    }

    @Test
    void validateConfigShouldPassWhenIncludedTermsAndConditionsIsSet() {
        when(configurationService.getBulkUserEmailIncludedTermsAndConditions())
                .thenReturn(List.of("1.5", "1.6"));

        loader.validateConfig();
    }

    @Test
    void loadUsersShouldCallDynamoServiceWithCorrectParameters() {
        when(configurationService.getBulkUserEmailIncludedTermsAndConditions())
                .thenReturn(List.of("1.5", "1.6"));
        loader.validateConfig();

        var exclusiveStartKey =
                Map.of("Email", AttributeValue.builder().s("test@example.com").build());
        var tableToScan = DynamoTable.USER_PROFILE;
        var expectedStream = Stream.<UserProfile>empty();
        when(dynamoService.getBulkUserEmailAudienceStreamOnTermsAndConditionsVersion(
                        exclusiveStartKey, List.of("1.5", "1.6")))
                .thenReturn(expectedStream);

        var result = loader.loadUsers(exclusiveStartKey, tableToScan);

        assertEquals(expectedStream, result);
        verify(dynamoService)
                .getBulkUserEmailAudienceStreamOnTermsAndConditionsVersion(
                        exclusiveStartKey, List.of("1.5", "1.6"));
    }

    @Test
    void loadUsersShouldPassNullExclusiveStartKeyForFirstBatch() {
        when(configurationService.getBulkUserEmailIncludedTermsAndConditions())
                .thenReturn(List.of("1.5"));
        loader.validateConfig();

        when(dynamoService.getBulkUserEmailAudienceStreamOnTermsAndConditionsVersion(
                        null, List.of("1.5")))
                .thenReturn(Stream.empty());

        var tableToScan = DynamoTable.USER_PROFILE;
        loader.loadUsers(null, tableToScan);

        verify(dynamoService)
                .getBulkUserEmailAudienceStreamOnTermsAndConditionsVersion(null, List.of("1.5"));
    }
}
