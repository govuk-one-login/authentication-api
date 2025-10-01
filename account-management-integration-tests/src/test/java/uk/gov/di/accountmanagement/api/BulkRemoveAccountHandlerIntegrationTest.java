package uk.gov.di.accountmanagement.api;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.AccountDeletionReason;
import uk.gov.di.accountmanagement.entity.BulkUserDeleteRequest;
import uk.gov.di.accountmanagement.entity.BulkUserDeleteResponse;
import uk.gov.di.accountmanagement.entity.DeletedAccountIdentifiers;
import uk.gov.di.accountmanagement.lambda.BulkRemoveAccountHandler;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.sharedtest.basetest.HandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper;
import uk.gov.di.authentication.sharedtest.helper.AuditEventExpectation;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_DELETE_ACCOUNT;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;

public class BulkRemoveAccountHandlerIntegrationTest
        extends HandlerIntegrationTest<BulkUserDeleteRequest, BulkUserDeleteResponse> {

    private static final String EMAIL_1 = "user1@example.com";
    private static final String EMAIL_2 = "user2@example.com";
    private static final String EMAIL_3 = "user3@example.com";
    private static final String EMAIL_4 = "user4@example.com";
    private static final String EMAIL_5 = "user5@example.com";
    private static final String PASSWORD = "password123";

    @BeforeEach
    void setup() {
        handler = new BulkRemoveAccountHandler(BULK_DELETION_TXMA_ENABLED_CONFIGUARION_SERVICE);
        txmaAuditQueue.clear();
        notificationsQueue.clear();
        snsTopicExtension.clearRequests();
    }

    @Test
    void shouldDeleteUsersWithinDateRange() {
        userStore.signUpWithCreationDate(EMAIL_1, PASSWORD, new Subject(), "2023-12-15T12:00:00");
        userStore.signUpWithCreationDate(EMAIL_2, PASSWORD, new Subject(), "2024-07-20T10:30:00");
        userStore.signUpWithCreationDate(EMAIL_3, PASSWORD, new Subject(), "2024-08-10T14:15:00");
        userStore.signUpWithCreationDate(EMAIL_4, PASSWORD, new Subject(), "2024-08-10T14:15:00");
        userStore.signUpWithCreationDate(EMAIL_5, PASSWORD, new Subject(), "2025-01-01T14:15:00");

        assertTrue(userStore.userExists(EMAIL_1));
        assertTrue(userStore.userExists(EMAIL_2));
        assertTrue(userStore.userExists(EMAIL_3));
        assertTrue(userStore.userExists(EMAIL_4));
        assertTrue(userStore.userExists(EMAIL_5));

        var request =
                new BulkUserDeleteRequest(
                        "TEST_REF_001",
                        List.of(EMAIL_1, EMAIL_2, EMAIL_3, EMAIL_4, EMAIL_5),
                        LocalDateTime.of(2024, 1, 1, 0, 0),
                        LocalDateTime.of(2024, 12, 31, 23, 59));

        BulkUserDeleteResponse result = handler.handleRequest(request, context);

        assertTrue(userStore.userExists(EMAIL_1));
        assertFalse(userStore.userExists(EMAIL_2));
        assertFalse(userStore.userExists(EMAIL_3));
        assertFalse(userStore.userExists(EMAIL_4));
        assertTrue(userStore.userExists(EMAIL_5));

        assertEquals(3, result.numberProcessed());
        assertEquals(2, result.numberFilteredOut());
        assertTrue(result.message().contains("TEST_REF_001"));

        assertAuditEvents(List.of(AUTH_DELETE_ACCOUNT, AUTH_DELETE_ACCOUNT, AUTH_DELETE_ACCOUNT));
        assertProcessedAccountIdentifiers(result.processedAccountIdentifiers(), 3);
    }

    @Test
    void shouldFilterOutUsersOutsideDateRangeWithEdgeCases() {
        userStore.signUpWithCreationDate(EMAIL_1, PASSWORD, new Subject(), "2019-12-31T23:59:59");
        userStore.signUpWithCreationDate(EMAIL_2, PASSWORD, new Subject(), "2020-01-01T00:00:00");
        userStore.signUpWithCreationDate(EMAIL_3, PASSWORD, new Subject(), "2020-12-31T23:59:59");
        userStore.signUpWithCreationDate(EMAIL_4, PASSWORD, new Subject(), "2021-01-01T00:00:00");

        assertTrue(userStore.userExists(EMAIL_1));
        assertTrue(userStore.userExists(EMAIL_2));
        assertTrue(userStore.userExists(EMAIL_3));
        assertTrue(userStore.userExists(EMAIL_4));

        var request =
                new BulkUserDeleteRequest(
                        "TEST_REF_002",
                        List.of(EMAIL_1, EMAIL_2, EMAIL_3, EMAIL_4),
                        LocalDateTime.of(2020, 1, 1, 0, 0, 0),
                        LocalDateTime.of(2020, 12, 31, 23, 59, 59));

        BulkUserDeleteResponse result = handler.handleRequest(request, context);

        assertTrue(userStore.userExists(EMAIL_1));
        assertFalse(userStore.userExists(EMAIL_2));
        assertFalse(userStore.userExists(EMAIL_3));
        assertTrue(userStore.userExists(EMAIL_4));

        assertEquals(2, result.numberProcessed());
        assertEquals(2, result.numberFilteredOut());

        assertAuditEvents(List.of(AUTH_DELETE_ACCOUNT, AUTH_DELETE_ACCOUNT));
        assertProcessedAccountIdentifiers(result.processedAccountIdentifiers(), 2);
    }

    @Test
    void shouldNotDeleteUsersNotFoundInTheDatabase() {
        userStore.signUpWithCreationDate(EMAIL_1, PASSWORD, new Subject(), "2024-04-07T12:00:00");
        userStore.signUpWithCreationDate(EMAIL_2, PASSWORD, new Subject(), "2024-07-20T10:30:00");
        userStore.signUpWithCreationDate(EMAIL_3, PASSWORD, new Subject(), "2024-08-10T14:15:00");

        assertTrue(userStore.userExists(EMAIL_1));
        assertTrue(userStore.userExists(EMAIL_2));
        assertTrue(userStore.userExists(EMAIL_3));

        var request =
                new BulkUserDeleteRequest(
                        "TEST_REF_001",
                        List.of(EMAIL_1, EMAIL_2, EMAIL_3, EMAIL_4, EMAIL_5),
                        LocalDateTime.of(2024, 1, 1, 0, 0),
                        LocalDateTime.of(2024, 12, 31, 23, 59));

        BulkUserDeleteResponse result = handler.handleRequest(request, context);

        assertFalse(userStore.userExists(EMAIL_1));
        assertFalse(userStore.userExists(EMAIL_2));
        assertFalse(userStore.userExists(EMAIL_3));
        assertFalse(userStore.userExists(EMAIL_4));
        assertFalse(userStore.userExists(EMAIL_5));

        assertEquals(3, result.numberProcessed());
        assertEquals(2, result.numberNotFound());
        assertTrue(result.message().contains("TEST_REF_001"));

        assertAuditEvents(List.of(AUTH_DELETE_ACCOUNT, AUTH_DELETE_ACCOUNT, AUTH_DELETE_ACCOUNT));
        assertProcessedAccountIdentifiers(result.processedAccountIdentifiers(), 3);
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

        AuditAssertionsHelper.assertNoTxmaAuditEventsReceived(txmaAuditQueue);
    }

    @Test
    void shouldHandleLargeNumberOfUsers() {
        for (int i = 1; i <= 60; i++) {
            String email = "user" + i + "@example.com";
            userStore.signUpWithCreationDate(email, PASSWORD, new Subject(), "2024-06-15T12:00:00");
            assertTrue(userStore.userExists(email));
        }

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

        BulkUserDeleteResponse result = handler.handleRequest(request, context);

        for (String email : emailsToDelete) {
            assertFalse(userStore.userExists(email));
        }

        assertTrue(userStore.userExists("user4@example.com"));
        assertTrue(userStore.userExists("user60@example.com"));

        assertTrue(result.message().contains("Processed: 6"));
        assertTrue(result.message().contains("Failed: 0"));

        assertEquals(6, result.numberProcessed());
        assertEquals(0, result.numberFailed());

        assertAuditEvents(
                List.of(
                        AUTH_DELETE_ACCOUNT,
                        AUTH_DELETE_ACCOUNT,
                        AUTH_DELETE_ACCOUNT,
                        AUTH_DELETE_ACCOUNT,
                        AUTH_DELETE_ACCOUNT,
                        AUTH_DELETE_ACCOUNT));
        assertProcessedAccountIdentifiers(result.processedAccountIdentifiers(), 6);
    }

    private static void assertAuditEvents(Collection<AuditableEvent> events) {
        List<String> receivedEvents = assertTxmaAuditEventsReceived(txmaAuditQueue, events, false);
        AuditEventExpectation expectation =
                new AuditEventExpectation(AccountManagementAuditableEvent.AUTH_DELETE_ACCOUNT);
        expectation.withAttribute(
                "extensions.account_deletion_reason",
                AccountDeletionReason.SECURITY_INITIATED.name());
        expectation.assertPublished(receivedEvents);
    }

    private static void assertProcessedAccountIdentifiers(
            List<DeletedAccountIdentifiers> processedAccountIdentifiers, int expectedProcessed) {
        assertEquals(expectedProcessed, processedAccountIdentifiers.size());
        for (var processedAccountIdentifier : processedAccountIdentifiers) {
            assertNotNull(processedAccountIdentifier.publicSubjectId());
            assertNotNull(processedAccountIdentifier.subjectId());
        }
    }
}
