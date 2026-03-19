package uk.gov.di.authentication.utils.services.audienceloader;

import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.utils.domain.DynamoTable;
import uk.gov.di.authentication.utils.entity.BulkUserEmailAudienceUser;

import java.util.Map;
import java.util.stream.Stream;

public interface BulkEmailAudienceLoader {

    void validateConfig();

    Stream<BulkUserEmailAudienceUser> loadUsers(
            Map<String, AttributeValue> exclusiveStartKey, DynamoTable tableToScan);
}
