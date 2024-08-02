package uk.gov.di.authentication.utils;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.S3Event;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.sharedtest.basetest.HandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.BulkTestUserS3Extension;
import uk.gov.di.authentication.sharedtest.helper.S3TestEventHelper;
import uk.gov.di.authentication.utils.lambda.BulkTestUserCreateHandler;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static uk.gov.di.authentication.sharedtest.extensions.BulkTestUserS3Extension.BULK_TEST_USER_BUCKET;
import static uk.gov.di.authentication.sharedtest.extensions.BulkTestUserS3Extension.TEST_FILE_NAME;
import static uk.gov.di.authentication.testsupport.helpers.BulkTestUserCsvHelper.getTestUsersProfilesAndCredentials;

class BulkTestUserCreateIntegrationTest extends HandlerIntegrationTest<S3Event, Void> {
    private static final S3Event testS3Event =
            S3TestEventHelper.generateS3TestEvent(
                    s3.getRegion(), "ObjectCreated:Put", BULK_TEST_USER_BUCKET, TEST_FILE_NAME);

    @RegisterExtension
    protected static final BulkTestUserS3Extension bulkTestUserS3 = new BulkTestUserS3Extension();

    @BeforeEach
    void setup() {
        handler = new BulkTestUserCreateHandler(TEST_CONFIGURATION_SERVICE, s3.getS3Client());
    }

    @Test
    void movedS3UserProfilesAndCredentialsIntoDynamoWhenTriggered() throws Exception {
        handler.handleRequest(testS3Event, mock(Context.class));
        Map<UserProfile, UserCredentials> testUsers = getTestUsersProfilesAndCredentials();

        List<UserProfile> userStoreAllTestUsers = userStore.getAllTestUsers();
        assertEquals(testUsers.size(), userStoreAllTestUsers.size());
        assertEquals(1, userStoreAllTestUsers.get(0).getTestUser());
    }
}
