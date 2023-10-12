package uk.gov.di.authentication.utils;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.extensions.BulkEmailUsersExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.utils.lambda.BulkUserEmailSenderScheduledEventHandler.DELIVERY_RECEIPT_STATUS_TEMPORARY_FAILURE;

public class BulkEmailUsersIntegrationTest {

    public static final String SUBJECT_ID_1 = "subject-id-1";
    public static final String SUBJECT_ID_2 = "subject-id-2";
    public static final String SUBJECT_ID_3 = "subject-id-3";
    public static final String SUBJECT_ID_4 = "subject-id-4";
    public static final String SUBJECT_ID_5 = "subject-id-5";

    @RegisterExtension
    protected static final BulkEmailUsersExtension bulkEmailUsersExtension =
            new BulkEmailUsersExtension();

    private Instant fixedNow = LocalDateTime.of(2023, 1, 1, 0, 0, 0).toInstant(ZoneOffset.UTC);

    private ConfigurationService configurationService =
            new ConfigurationService() {
                @Override
                public Clock getClock() {
                    return Clock.fixed(fixedNow, ZoneId.of("UTC"));
                }
            };

    BulkEmailUsersService bulkEmailUsersService = new BulkEmailUsersService(configurationService);

    @Test
    void shouldAddBulkEmailUserWithPendingStatusAndCreatedTimestamp() {
        bulkEmailUsersService.addUser(SUBJECT_ID_1, BulkEmailStatus.PENDING);

        var createdUser = bulkEmailUsersService.getBulkEmailUsers(SUBJECT_ID_1).get();

        assertEquals(SUBJECT_ID_1, createdUser.getSubjectID());
        assertEquals(BulkEmailStatus.PENDING, createdUser.getBulkEmailStatus());
        assertEquals(
                LocalDateTime.ofInstant(fixedNow, ZoneId.of("UTC")).toString(),
                createdUser.getCreatedAt());
    }

    @Test
    void updateUserStatusUpdatesaUserWithTheProvidedStatus() {
        bulkEmailUsersExtension.addBulkEmailUser(SUBJECT_ID_1, BulkEmailStatus.PENDING);

        var updatedUser =
                bulkEmailUsersService
                        .updateUserStatus(SUBJECT_ID_1, BulkEmailStatus.EMAIL_SENT)
                        .get();

        assertEquals(SUBJECT_ID_1, updatedUser.getSubjectID());
        assertEquals(BulkEmailStatus.EMAIL_SENT, updatedUser.getBulkEmailStatus());

        var bulkEmailUserAfterUpdate = bulkEmailUsersService.getBulkEmailUsers(SUBJECT_ID_1).get();

        assertEquals(BulkEmailStatus.EMAIL_SENT, bulkEmailUserAfterUpdate.getBulkEmailStatus());
        assertEquals(
                LocalDateTime.ofInstant(fixedNow, ZoneId.of("UTC")).toString(),
                bulkEmailUserAfterUpdate.getUpdatedAt());
    }

    @Test
    void updateDeliveryStatusUpdatesAUserWithTheProvidedDeliveryStatus() {
        bulkEmailUsersExtension.addBulkEmailUser(SUBJECT_ID_1, BulkEmailStatus.PENDING);

        String deliveryStatus = "delivered";

        var updatedUser =
                bulkEmailUsersService
                        .updateDeliveryReceiptStatus(SUBJECT_ID_1, deliveryStatus)
                        .get();

        assertEquals(SUBJECT_ID_1, updatedUser.getSubjectID());
        assertEquals(deliveryStatus, updatedUser.getDeliveryReceiptStatus());
    }

    @Test
    void updateUserStatusReturnsNoneIfTheSuppliedSubjectIdDoesNotExist() {
        var subjectId = "a-non-existent-subject-id";
        var result = bulkEmailUsersService.updateUserStatus(subjectId, BulkEmailStatus.EMAIL_SENT);

        assertEquals(result, Optional.empty());
    }

    @Test
    void shouldReturnBulkListOfUsersPending() {
        bulkEmailUsersExtension.addBulkEmailUser(SUBJECT_ID_1, BulkEmailStatus.PENDING);
        bulkEmailUsersExtension.addBulkEmailUser(SUBJECT_ID_2, BulkEmailStatus.PENDING);
        bulkEmailUsersExtension.addBulkEmailUser(SUBJECT_ID_3, BulkEmailStatus.EMAIL_SENT);

        var subjectIds = bulkEmailUsersService.getNSubjectIdsByStatus(5, BulkEmailStatus.PENDING);

        assertEquals(2, subjectIds.size());
        assertThat(subjectIds, containsInAnyOrder(SUBJECT_ID_1, SUBJECT_ID_2));
    }

    @Test
    void shouldReturnBulkListOfUsersWithLimit() {
        bulkEmailUsersExtension.addBulkEmailUser(SUBJECT_ID_1, BulkEmailStatus.PENDING);
        bulkEmailUsersExtension.addBulkEmailUser(SUBJECT_ID_2, BulkEmailStatus.PENDING);
        bulkEmailUsersExtension.addBulkEmailUser(SUBJECT_ID_3, BulkEmailStatus.EMAIL_SENT);
        bulkEmailUsersExtension.addBulkEmailUser(SUBJECT_ID_4, BulkEmailStatus.PENDING);
        bulkEmailUsersExtension.addBulkEmailUser(SUBJECT_ID_5, BulkEmailStatus.PENDING);

        var limit = 3;

        var users = bulkEmailUsersService.getNSubjectIdsByStatus(limit, BulkEmailStatus.PENDING);

        assertEquals(limit, users.size());
    }

    @Test
    void shouldReturnUsersWithStatusOfEmailSentAndRelevantDeliveryReceiptStatus() {
        String temporaryFailureString = "temporary-failure";
        String permanentFailureString = "permanent-failure";
        bulkEmailUsersExtension.addBulkEmailUserWithDeliveryReceiptStatus(
                SUBJECT_ID_1,
                DELIVERY_RECEIPT_STATUS_TEMPORARY_FAILURE,
                BulkEmailStatus.EMAIL_SENT);
        bulkEmailUsersExtension.addBulkEmailUserWithDeliveryReceiptStatus(
                SUBJECT_ID_2,
                DELIVERY_RECEIPT_STATUS_TEMPORARY_FAILURE,
                BulkEmailStatus.EMAIL_SENT);
        bulkEmailUsersExtension.addBulkEmailUserWithDeliveryReceiptStatus(
                SUBJECT_ID_3,
                DELIVERY_RECEIPT_STATUS_TEMPORARY_FAILURE,
                BulkEmailStatus.EMAIL_SENT);
        bulkEmailUsersExtension.addBulkEmailUserWithDeliveryReceiptStatus(
                SUBJECT_ID_4, permanentFailureString, BulkEmailStatus.EMAIL_SENT);
        bulkEmailUsersExtension.addBulkEmailUserWithDeliveryReceiptStatus(
                SUBJECT_ID_5, DELIVERY_RECEIPT_STATUS_TEMPORARY_FAILURE, BulkEmailStatus.PENDING);

        var users =
                bulkEmailUsersService.getNSubjectIdsByDeliveryReceiptStatus(
                        5, DELIVERY_RECEIPT_STATUS_TEMPORARY_FAILURE);

        assertEquals(3, users.size());
        assertEquals(Set.of(SUBJECT_ID_1, SUBJECT_ID_2, SUBJECT_ID_3), new HashSet<>(users));
    }

    @Test
    void shouldReturnTheCorrectNumberOfUsersByDeliveryReceiptStatus() {
        bulkEmailUsersExtension.addBulkEmailUserWithDeliveryReceiptStatus(
                SUBJECT_ID_1,
                DELIVERY_RECEIPT_STATUS_TEMPORARY_FAILURE,
                BulkEmailStatus.EMAIL_SENT);
        bulkEmailUsersExtension.addBulkEmailUserWithDeliveryReceiptStatus(
                SUBJECT_ID_2,
                DELIVERY_RECEIPT_STATUS_TEMPORARY_FAILURE,
                BulkEmailStatus.EMAIL_SENT);
        bulkEmailUsersExtension.addBulkEmailUserWithDeliveryReceiptStatus(
                SUBJECT_ID_3,
                DELIVERY_RECEIPT_STATUS_TEMPORARY_FAILURE,
                BulkEmailStatus.EMAIL_SENT);
        bulkEmailUsersExtension.addBulkEmailUserWithDeliveryReceiptStatus(
                SUBJECT_ID_4,
                DELIVERY_RECEIPT_STATUS_TEMPORARY_FAILURE,
                BulkEmailStatus.EMAIL_SENT);
        bulkEmailUsersExtension.addBulkEmailUserWithDeliveryReceiptStatus(
                SUBJECT_ID_5,
                DELIVERY_RECEIPT_STATUS_TEMPORARY_FAILURE,
                BulkEmailStatus.EMAIL_SENT);

        var limit = 3;
        var users =
                bulkEmailUsersService.getNSubjectIdsByDeliveryReceiptStatus(
                        limit, DELIVERY_RECEIPT_STATUS_TEMPORARY_FAILURE);

        assertEquals(limit, users.size());
    }
}
