package uk.gov.di.authentication.utils.services.audienceloader;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.utils.domain.DynamoTable;
import uk.gov.di.authentication.utils.entity.BulkUserEmailAudienceUser;

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
    public Stream<BulkUserEmailAudienceUser> loadUsers(
            Map<String, AttributeValue> exclusiveStartKey, DynamoTable tableToScan) {
        LOG.info("Loading users from table: {}", tableToScan.name());

        var sourceStream =
                switch (tableToScan) {
                    case USER_PROFILE -> dynamoService
                            .getBulkUserEmailAudienceUserProfileStreamOnInternationalNumber(
                                    exclusiveStartKey);
                    case USER_CREDENTIALS -> dynamoService
                            .getBulkUserEmailAudienceUserCredentialsStreamOnInternationalNumber(
                                    exclusiveStartKey);
                };

        return sourceStream.map(BulkUserEmailAudienceUser::from);
    }
}
