package uk.gov.di.authentication.utils;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.entity.BulkEmailUser;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.extensions.BulkEmailUsersExtension;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class BulkEmailUsersIntegrationTest {

    public static final String SUBJECT_ID_1 = "subject-id-1";
    public static final String SUBJECT_ID_2 = "subject-id-2";
    public static final String SUBJECT_ID_3 = "subject-id-3";
    public static final String SUBJECT_ID_4 = "subject-id-4";
    public static final String SUBJECT_ID_5 = "subject-id-5";

    @RegisterExtension
    protected static final BulkEmailUsersExtension bulkEmailUsersExtension =
            new BulkEmailUsersExtension();

    BulkEmailUsersService bulkEmailUsersService =
            new BulkEmailUsersService(ConfigurationService.getInstance());

    @Test
    void updateUserStatusUpdatesaUserWithTheProvidedStatus() {
        bulkEmailUsersExtension.addBulkEmailUser(SUBJECT_ID_1, BulkEmailStatus.PENDING);

        var updatedUser =
                bulkEmailUsersService
                        .updateUserStatus(SUBJECT_ID_1, BulkEmailStatus.EMAIL_SENT)
                        .get();

        assertEquals(updatedUser.getSubjectID(), SUBJECT_ID_1);
        assertEquals(updatedUser.getBulkEmailStatus(), BulkEmailStatus.EMAIL_SENT);

        var bulkEmailStatusOfUserAfterUpdate =
                bulkEmailUsersService
                        .getBulkEmailUsers(SUBJECT_ID_1)
                        .map(BulkEmailUser::getBulkEmailStatus)
                        .get();

        assertEquals(bulkEmailStatusOfUserAfterUpdate, bulkEmailStatusOfUserAfterUpdate.EMAIL_SENT);
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
}
