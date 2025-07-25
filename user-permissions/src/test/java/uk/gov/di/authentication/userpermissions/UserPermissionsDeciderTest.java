package uk.gov.di.authentication.userpermissions;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.userpermissions.entity.Decision;
import uk.gov.di.authentication.userpermissions.entity.ForbiddenReason;
import uk.gov.di.authentication.userpermissions.entity.UserPermissionContext;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UserPermissionsDeciderTest {

    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_SUBJECT_ID = "subject123";
    private static final String TEST_RP_PAIRWISE_ID = "rp123";

    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private UserPermissionsDecider userPermissionsDecider;
    private UserPermissionContext userPermissionContext;

    @BeforeEach
    void setUp() {
        userPermissionsDecider = new UserPermissionsDecider(codeStorageService);
        userPermissionContext =
                UserPermissionContext.builder()
                        .withEmailAddress(TEST_EMAIL)
                        .withInternalSubjectId(TEST_SUBJECT_ID)
                        .withRpPairwiseId(TEST_RP_PAIRWISE_ID)
                        .withAuthSessionItem(new AuthSessionItem())
                        .build();
    }

    @Nested
    class PasswordReceiving {
        @Test
        void shouldReturnPermitted_whenNotBlocked() {
            // Given
            when(codeStorageService.isBlockedForEmail(
                            TEST_EMAIL,
                            CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX
                                    + JourneyType.PASSWORD_RESET))
                    .thenReturn(false);

            // When
            var result =
                    userPermissionsDecider.canReceivePassword(
                            JourneyType.SIGN_IN, userPermissionContext);

            // Then
            assertThat("Should allow password when not blocked", result.isSuccess(), is(true));
            assertThat(result.getSuccess(), instanceOf(Decision.Permitted.class));
            assertThat(result.getSuccess().attemptCount(), equalTo(0));
        }

        @Test
        void shouldReturnTemporarilyLockedOut_whenBlocked() {
            // Given
            when(codeStorageService.isBlockedForEmail(
                            TEST_EMAIL,
                            CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX
                                    + JourneyType.PASSWORD_RESET))
                    .thenReturn(true);

            // When
            var result =
                    userPermissionsDecider.canReceivePassword(
                            JourneyType.SIGN_IN, userPermissionContext);

            // Then
            assertThat(
                    "Should return successful result even when locked out",
                    result.isSuccess(),
                    is(true));
            var decision = result.getSuccess();
            assertThat(decision, instanceOf(Decision.TemporarilyLockedOut.class));
            var lockedOut = (Decision.TemporarilyLockedOut) decision;
            assertThat(
                    lockedOut.forbiddenReason(),
                    equalTo(ForbiddenReason.EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT));
            assertThat(lockedOut.attemptCount(), equalTo(0));
        }
    }
}
