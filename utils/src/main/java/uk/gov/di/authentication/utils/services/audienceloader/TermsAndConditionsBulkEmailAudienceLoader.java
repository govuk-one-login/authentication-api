package uk.gov.di.authentication.utils.services.audienceloader;

import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.utils.domain.DynamoTable;
import uk.gov.di.authentication.utils.exceptions.IncludedTermsAndConditionsConfigMissingException;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public class TermsAndConditionsBulkEmailAudienceLoader implements BulkEmailAudienceLoader {

    private final ConfigurationService configurationService;
    private final DynamoService dynamoService;
    private List<String> includedTermsAndConditions;

    public TermsAndConditionsBulkEmailAudienceLoader(
            ConfigurationService configurationService, DynamoService dynamoService) {
        this.configurationService = configurationService;
        this.dynamoService = dynamoService;
    }

    @Override
    public void validateConfig() {
        includedTermsAndConditions =
                configurationService.getBulkUserEmailIncludedTermsAndConditions();
        if (includedTermsAndConditions == null || includedTermsAndConditions.isEmpty()) {
            throw new IncludedTermsAndConditionsConfigMissingException();
        }
    }

    @Override
    public Stream<UserProfile> loadUsers(
            Map<String, AttributeValue> exclusiveStartKey, DynamoTable tableToScan) {
        if (tableToScan != DynamoTable.USER_PROFILE) {
            throw new IllegalArgumentException("Only USER_PROFILE table supported.");
        }

        return dynamoService.getBulkUserEmailAudienceStreamOnTermsAndConditionsVersion(
                exclusiveStartKey, includedTermsAndConditions);
    }
}
