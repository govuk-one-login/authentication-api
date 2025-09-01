package uk.gov.di.accountmanagement.api;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.BulkUserDeleteRequest;
import uk.gov.di.accountmanagement.lambda.BulkRemoveAccountHandler;
import uk.gov.di.authentication.sharedtest.basetest.HandlerIntegrationTest;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BulkRemoveAccountHandlerIntegrationTest
        extends HandlerIntegrationTest<BulkUserDeleteRequest, String> {

    private static final String EMAIL_1 = "user1@example.com";
    private static final String EMAIL_2 = "user2@example.com";
    private static final String EMAIL_3 = "user3@example.com";
    private static final String EMAIL_4 = "nonexistent@example.com";
    private static final String PASSWORD = "password123";

    @BeforeEach
    void setup() {
        handler = new BulkRemoveAccountHandler(BULK_DELETION_TXMA_ENABLED_CONFIGUARION_SERVICE);
        txmaAuditQueue.clear();
        notificationsQueue.clear();
        snsTopicExtension.clearRequests();
    }

    @Test
    void shouldDeleteUsersWithinDateRangeAndLeaveOthersUntouched() {
        // Create test users with creation dates within range
        userStore.signUpWithCreationDate(EMAIL_1, PASSWORD, new Subject(), "2024-06-15T12:00:00");
        userStore.signUpWithCreationDate(EMAIL_2, PASSWORD, new Subject(), "2024-07-20T10:30:00");
        userStore.signUpWithCreationDate(EMAIL_3, PASSWORD, new Subject(), "2024-08-10T14:15:00");

        // Verify users exist before deletion
        assertTrue(userStore.userExists(EMAIL_1));
        assertTrue(userStore.userExists(EMAIL_2));
        assertTrue(userStore.userExists(EMAIL_3));

        var request =
                new BulkUserDeleteRequest(
                        "TEST_REF_001",
                        List.of(EMAIL_1, EMAIL_2, EMAIL_4),
                        LocalDateTime.of(2024, 1, 1, 0, 0),
                        LocalDateTime.of(2024, 12, 31, 23, 59));

        String result = handler.handleRequest(request, context);

        // Verify correct users were deleted
        assertFalse(userStore.userExists(EMAIL_1));
        assertFalse(userStore.userExists(EMAIL_2));
        assertTrue(userStore.userExists(EMAIL_3)); // Not in deletion list

        // Verify result message
        assertTrue(result.contains("Processed: 2"));
        assertTrue(result.contains("Not found: 1"));
        assertTrue(result.contains("TEST_REF_001"));
    }

    @Test
    void shouldFilterOutUsersOutsideDateRange() {
        // Create test user with creation date outside the range
        userStore.signUpWithCreationDate(EMAIL_1, PASSWORD, new Subject(), "2019-06-15T12:00:00");
        assertTrue(userStore.userExists(EMAIL_1));

        // Request with date range that excludes the user
        var request =
                new BulkUserDeleteRequest(
                        "TEST_REF_002",
                        List.of(EMAIL_1),
                        LocalDateTime.of(2020, 1, 1, 0, 0),
                        LocalDateTime.of(2020, 12, 31, 23, 59));

        String result = handler.handleRequest(request, context);

        // User should still exist (filtered out)
        assertTrue(userStore.userExists(EMAIL_1));
        assertTrue(result.contains("Filtered out: 1"));
        assertTrue(result.contains("Processed: 0"));
    }

    @Test
    void shouldHandleEmptyEmailList() {
        var request =
                new BulkUserDeleteRequest(
                        "TEST_REF_003",
                        List.of(),
                        LocalDateTime.of(2020, 1, 1, 0, 0),
                        LocalDateTime.of(2030, 12, 31, 23, 59));

        try {
            handler.handleRequest(request, context);
        } catch (RuntimeException e) {
            assertTrue(
                    e.getMessage().contains("Bulk deletion failed")
                            && e.getCause()
                                    .getMessage()
                                    .contains("Email list cannot be null or empty"));
        }
    }

    @Test
    void shouldHandleLargeNumberOfUsers() {
        // Create multiple users to test batch processing
        for (int i = 1; i <= 60; i++) {
            String email = "user" + i + "@example.com";
            userStore.signUpWithCreationDate(email, PASSWORD, new Subject(), "2024-06-15T12:00:00");
            assertTrue(userStore.userExists(email));
        }

        // Create list of emails to delete
        List<String> emailsToDelete =
                List.of(
                        "user1@example.com",
                        "user2@example.com",
                        "user3@example.com",
                        "user51@example.com",
                        "user52@example.com",
                        "user53@example.com");

        var request =
                new BulkUserDeleteRequest(
                        "TEST_REF_004",
                        emailsToDelete,
                        LocalDateTime.of(2024, 1, 1, 0, 0),
                        LocalDateTime.of(2024, 12, 31, 23, 59));

        String result = handler.handleRequest(request, context);

        // Verify specified users were deleted
        for (String email : emailsToDelete) {
            assertFalse(userStore.userExists(email));
        }

        // Verify other users still exist
        assertTrue(userStore.userExists("user4@example.com"));
        assertTrue(userStore.userExists("user60@example.com"));

        assertTrue(result.contains("Processed: 6"));
        assertTrue(result.contains("Failed: 0"));
    }
}
