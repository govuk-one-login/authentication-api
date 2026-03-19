package uk.gov.di.authentication.utils.services.audienceloader;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.utils.domain.DynamoTable;

import java.util.Map;
import java.util.stream.Stream;

public class InternationalNumbersForcedMfaResetBulkEmailAudienceLoader
        implements BulkEmailAudienceLoader {

    private static final Logger LOG =
            LogManager.getLogger(InternationalNumbersForcedMfaResetBulkEmailAudienceLoader.class);

    private final DynamoService dynamoService;

    public InternationalNumbersForcedMfaResetBulkEmailAudienceLoader(DynamoService dynamoService) {
        this.dynamoService = dynamoService;
    }

    @Override
    public void validateConfig() {
        // No additional config required yet
    }

    @Override
    public Stream<UserProfile> loadUsers(
            Map<String, AttributeValue> exclusiveStartKey, DynamoTable tableToScan) {
        // TODO (future commit): Remove this guard once USER_CREDENTIALS supported.
        if (tableToScan != DynamoTable.USER_PROFILE) {
            throw new IllegalArgumentException("Only USER_PROFILE table supported (at present).");
        }

        LOG.info("Loading users from table: {}", tableToScan.name());

        return dynamoService.getBulkUserEmailAudienceUserProfileStreamOnInternationalNumber(
                exclusiveStartKey);
    }
}
