package uk.gov.di.authentication.utils.services.audienceloader;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.utils.domain.DynamoTable;

import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class InternationalNumbersForcedMfaResetBulkEmailAudienceLoaderTest {

    private final DynamoService dynamoService = mock(DynamoService.class);
    private final InternationalNumbersForcedMfaResetBulkEmailAudienceLoader loader =
            new InternationalNumbersForcedMfaResetBulkEmailAudienceLoader(dynamoService);

    @Test
    void validateConfigShouldNotThrow() {
        assertDoesNotThrow(loader::validateConfig);
    }

    @Test
    void loadUsersShouldCallDynamoServiceWithCorrectExclusiveStartKey() {
        DynamoTable tableToScan = DynamoTable.USER_PROFILE;
        var exclusiveStartKey =
                Map.of("Email", AttributeValue.builder().s("test@example.com").build());
        var expectedStream = Stream.<UserProfile>empty();
        when(dynamoService.getBulkUserEmailAudienceUserProfileStreamOnInternationalNumber(
                        exclusiveStartKey))
                .thenReturn(expectedStream);

        var result = loader.loadUsers(exclusiveStartKey, tableToScan);

        assertEquals(expectedStream, result);
        verify(dynamoService)
                .getBulkUserEmailAudienceUserProfileStreamOnInternationalNumber(exclusiveStartKey);
    }

    @Test
    void loadUsersShouldPassNullExclusiveStartKeyForFirstBatch() {
        DynamoTable tableToScan = DynamoTable.USER_PROFILE;
        when(dynamoService.getBulkUserEmailAudienceUserProfileStreamOnInternationalNumber(null))
                .thenReturn(Stream.empty());

        loader.loadUsers(null, tableToScan);

        verify(dynamoService).getBulkUserEmailAudienceUserProfileStreamOnInternationalNumber(null);
    }

    @Test
    void loadUsersShouldReturnStreamFromDynamoServiceForInternationalNumber() {
        DynamoTable tableToScan = DynamoTable.USER_PROFILE;

        var userWithInternationalNumber = new UserProfile();
        userWithInternationalNumber.setEmail("international@example.com");
        userWithInternationalNumber.setSubjectID("subject-1");

        var exclusiveStartKey =
                Map.of("SubjectID", AttributeValue.builder().s("subject-0").build());
        var expectedStream = Stream.of(userWithInternationalNumber);
        when(dynamoService.getBulkUserEmailAudienceUserProfileStreamOnInternationalNumber(
                        exclusiveStartKey))
                .thenReturn(expectedStream);

        var result = loader.loadUsers(exclusiveStartKey, tableToScan);

        assertEquals(expectedStream, result);
    }

    @Test
    void loadUsersShouldDelegateMultipleUsersFromDynamoService() {
        DynamoTable tableToScan = DynamoTable.USER_PROFILE;

        var user1 = new UserProfile();
        user1.setEmail("user1@example.com");
        user1.setSubjectID("subject-1");

        var user2 = new UserProfile();
        user2.setEmail("user2@example.com");
        user2.setSubjectID("subject-2");

        var expectedStream = Stream.of(user1, user2);
        when(dynamoService.getBulkUserEmailAudienceUserProfileStreamOnInternationalNumber(null))
                .thenReturn(expectedStream);

        var result = loader.loadUsers(null, tableToScan);

        assertEquals(expectedStream, result);
    }
}
