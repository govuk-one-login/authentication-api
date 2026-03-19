package uk.gov.di.authentication.utils.services.audienceloader;

import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.shared.entity.UserProfile;

import java.util.Map;
import java.util.stream.Stream;

public class InternationalNumbersForcedMfaResetBulkEmailAudienceLoader implements BulkEmailAudienceLoader {

    @Override
    public void validateConfig() {
        // No additional config required yet
    }

    @Override
    public Stream<UserProfile> loadUsers(Map<String, AttributeValue> exclusiveStartKey) {
        throw new UnsupportedOperationException(
                "International numbers forced MFA reset audience loading not yet implemented");
    }
}
