package uk.gov.di.authentication.utils.services.audienceloader;

import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.shared.entity.UserProfile;

import java.util.Map;
import java.util.stream.Stream;

public interface BulkEmailAudienceLoader {

    void validateConfig();

    Stream<UserProfile> loadUsers(Map<String, AttributeValue> exclusiveStartKey);
}
