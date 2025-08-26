package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.DeletedAccountIdentifiers;
import uk.gov.di.accountmanagement.services.ManualAccountDeletionService;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuthenticationService;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class BulkRemoveAccountHandlerTest {

    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ManualAccountDeletionService manualAccountDeletionService =
            mock(ManualAccountDeletionService.class);
    private final Context context = mock(Context.class);

    private BulkRemoveAccountHandler handler;

    @BeforeEach
    void setUp() {
        handler = new BulkRemoveAccountHandler(authenticationService, manualAccountDeletionService);
        when(context.getAwsRequestId()).thenReturn("test-request-id");
    }

    @Nested
    @DisplayName("Request Validation")
    class RequestValidation {

        @Test
        @DisplayName("Should throw exception when reference is empty")
        void shouldThrowExceptionWhenReferenceIsEmpty() {
            String input =
                    """
                {
                    "reference": "   ",
                    "emails": ["test@example.com"],
                    "created_after": "2024-01-01T00:00:00",
                    "created_before": "2024-12-31T23:59:59"
                }
                """;

            RuntimeException exception =
                    assertThrows(
                            RuntimeException.class, () -> handler.handleRequest(input, context));

            assertTrue(
                    exception
                            .getCause()
                            .getMessage()
                            .contains("Reference cannot be null or empty"));
        }

        @Test
        @DisplayName("Should throw exception when emails list is empty")
        void shouldThrowExceptionWhenEmailsListIsEmpty() {
            String input =
                    """
                {
                    "reference": "TEST_REF",
                    "emails": [],
                    "created_after": "2024-01-01T00:00:00",
                    "created_before": "2024-12-31T23:59:59"
                }
                """;

            RuntimeException exception =
                    assertThrows(
                            RuntimeException.class, () -> handler.handleRequest(input, context));

            assertTrue(
                    exception
                            .getCause()
                            .getMessage()
                            .contains("Email list cannot be null or empty"));
        }

        @Test
        @DisplayName("Should throw exception when date format is invalid")
        void shouldThrowExceptionWhenDateFormatIsInvalid() {
            String input =
                    """
                {
                    "reference": "TEST_REF",
                    "emails": ["test@example.com"],
                    "created_after": "invalid-date",
                    "created_before": "2024-12-31T23:59:59"
                }
                """;

            RuntimeException exception =
                    assertThrows(
                            RuntimeException.class, () -> handler.handleRequest(input, context));

            assertTrue(exception.getMessage().contains("Bulk deletion failed"));
        }
    }

    @Nested
    @DisplayName("User Processing")
    class UserProcessing {

        @Test
        @DisplayName("Should successfully delete user within date range")
        void shouldSuccessfullyDeleteUserWithinDateRange() {
            String input =
                    """
                {
                    "reference": "TEST_REF",
                    "emails": ["test@example.com"],
                    "created_after": "2024-01-01T00:00:00",
                    "created_before": "2024-12-31T23:59:59"
                }
                """;

            UserProfile userProfile = createUserProfile("test@example.com", "2024-06-15T12:00:00");
            DeletedAccountIdentifiers identifiers =
                    new DeletedAccountIdentifiers("pub123", "leg123", "sub123");

            when(authenticationService.getUserProfileByEmailMaybe("test@example.com"))
                    .thenReturn(Optional.of(userProfile));
            when(manualAccountDeletionService.manuallyDeleteAccount(userProfile))
                    .thenReturn(identifiers);

            String result = handler.handleRequest(input, context);

            assertTrue(result.contains("Processed: 1"));
            assertTrue(result.contains("Failed: 0"));
            assertTrue(result.contains("Not found: 0"));
            assertTrue(result.contains("Filtered out: 0"));
            verify(manualAccountDeletionService).manuallyDeleteAccount(userProfile);
        }

        @Test
        @DisplayName("Should filter out user created before date range")
        void shouldFilterOutUserCreatedBeforeDateRange() {
            String input =
                    """
                {
                    "reference": "TEST_REF",
                    "emails": ["test@example.com"],
                    "created_after": "2024-06-01T00:00:00",
                    "created_before": "2024-12-31T23:59:59"
                }
                """;

            UserProfile userProfile = createUserProfile("test@example.com", "2024-05-15T12:00:00");

            when(authenticationService.getUserProfileByEmailMaybe("test@example.com"))
                    .thenReturn(Optional.of(userProfile));

            String result = handler.handleRequest(input, context);

            assertTrue(result.contains("Processed: 0"));
            assertTrue(result.contains("Failed: 0"));
            assertTrue(result.contains("Not found: 0"));
            assertTrue(result.contains("Filtered out: 1"));
            verify(manualAccountDeletionService, never()).manuallyDeleteAccount(any());
        }

        @Test
        @DisplayName("Should handle user not found")
        void shouldHandleUserNotFound() {
            String input =
                    """
                {
                    "reference": "TEST_REF",
                    "emails": ["nonexistent@example.com"],
                    "created_after": "2024-01-01T00:00:00",
                    "created_before": "2024-12-31T23:59:59"
                }
                """;

            when(authenticationService.getUserProfileByEmailMaybe("nonexistent@example.com"))
                    .thenReturn(Optional.empty());

            String result = handler.handleRequest(input, context);

            assertTrue(result.contains("Processed: 0"));
            assertTrue(result.contains("Failed: 0"));
            assertTrue(result.contains("Not found: 1"));
            assertTrue(result.contains("Filtered out: 0"));
            verify(manualAccountDeletionService, never()).manuallyDeleteAccount(any());
        }

        @Test
        @DisplayName("Should handle processing failure")
        void shouldHandleProcessingFailure() {
            String input =
                    """
                {
                    "reference": "TEST_REF",
                    "emails": ["test@example.com"],
                    "created_after": "2024-01-01T00:00:00",
                    "created_before": "2024-12-31T23:59:59"
                }
                """;

            UserProfile userProfile = createUserProfile("test@example.com", "2024-06-01T10:00:00");
            when(authenticationService.getUserProfileByEmailMaybe("test@example.com"))
                    .thenReturn(Optional.of(userProfile));
            when(manualAccountDeletionService.manuallyDeleteAccount(userProfile))
                    .thenThrow(new RuntimeException("Database error"));

            String result = handler.handleRequest(input, context);

            assertTrue(result.contains("Processed: 0"));
            assertTrue(result.contains("Failed: 1"));
            assertTrue(result.contains("Not found: 0"));
            assertTrue(result.contains("Filtered out: 0"));
            verify(manualAccountDeletionService).manuallyDeleteAccount(userProfile);
        }
    }

    private UserProfile createUserProfile(String email, String createdDate) {
        UserProfile userProfile = new UserProfile();
        userProfile.setEmail(email);
        userProfile.setCreated(createdDate);
        userProfile.setSubjectID("subject-123");
        userProfile.setPublicSubjectID("public-123");
        userProfile.setLegacySubjectID("legacy-123");
        return userProfile;
    }
}
