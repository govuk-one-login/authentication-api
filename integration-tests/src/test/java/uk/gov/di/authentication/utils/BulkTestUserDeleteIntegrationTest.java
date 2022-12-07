package uk.gov.di.authentication.utils;

import com.amazonaws.services.lambda.runtime.Context;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.sharedtest.basetest.HandlerIntegrationTest;
import uk.gov.di.authentication.utils.lambda.BulkTestUserDeleteHandler;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static uk.gov.di.authentication.testsupport.helpers.BulkTestUserCsvHelper.getTestUsersProfilesAndCredentials;

class BulkTestUserDeleteIntegrationTest extends HandlerIntegrationTest<String, Void> {
    private static final Logger LOG = LogManager.getLogger(BulkTestUserDeleteIntegrationTest.class);

    @BeforeEach
    void setup() throws Exception {
        setUpDynamoWithTestUsers();
        handler = new BulkTestUserDeleteHandler(TEST_CONFIGURATION_SERVICE);
    }

    private void setUpDynamoWithTestUsers() throws Exception {
        long startTime = System.nanoTime();
        Map<UserProfile, UserCredentials> bulkTestUsersToWriteToDb =
                getTestUsersProfilesAndCredentials();
        userStore.createBulkTestUsers(bulkTestUsersToWriteToDb);
        long endTime = System.nanoTime();
        long durationInMilliseconds = (endTime - startTime) / 1000000;
        LOG.info(
                "Integration test bulk user insert operation took {} ms for {} records",
                durationInMilliseconds,
                bulkTestUsersToWriteToDb.size());
    }

    @Test
    void allTestUsersAreDeleted() throws Exception {
        Map<UserProfile, UserCredentials> testUsers = getTestUsersProfilesAndCredentials();

        assertTrue(
                userStore.userExists(
                        testUsers.entrySet().stream().iterator().next().getKey().getEmail()));

        handler.handleRequest("test-input-string", mock(Context.class));

        testUsers.forEach((key, value) -> assertFalse(userStore.userExists(key.getEmail())));
    }
}
