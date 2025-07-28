package uk.gov.di.authentication.userpermissions;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.userpermissions.entity.Decision;
import uk.gov.di.authentication.userpermissions.entity.DecisionError;
import uk.gov.di.authentication.userpermissions.entity.ForbiddenReason;
import uk.gov.di.authentication.userpermissions.entity.UserPermissionContext;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PermissionDecisionManagerTest {

    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_SUBJECT_ID = "subject123";
    private static final String TEST_RP_PAIRWISE_ID = "rp123";

    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private PermissionDecisionManager permissionDecisionManager;
    private UserPermissionContext userPermissionContext;

    @BeforeEach
    void setUp() {
        permissionDecisionManager = new PermissionDecisionManager(codeStorageService);
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
                    permissionDecisionManager.canReceivePassword(
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
                    permissionDecisionManager.canReceivePassword(
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

        @Test
        void shouldReturnInvalidUserContext_whenUserPermissionContextIsNull() {
            // When
            var result = permissionDecisionManager.canReceivePassword(JourneyType.SIGN_IN, null);

            // Then
            assertThat("Should return failure for null context", result.isFailure(), is(true));
            assertThat(result.getFailure(), equalTo(DecisionError.INVALID_USER_CONTEXT));
        }

        @Test
        void shouldReturnInvalidUserContext_whenEmailAddressIsNull() {
            // Given
            var contextWithoutEmail =
                    UserPermissionContext.builder()
                            .withInternalSubjectId(TEST_SUBJECT_ID)
                            .withRpPairwiseId(TEST_RP_PAIRWISE_ID)
                            .withAuthSessionItem(new AuthSessionItem())
                            .build();

            // When
            var result =
                    permissionDecisionManager.canReceivePassword(
                            JourneyType.SIGN_IN, contextWithoutEmail);

            // Then
            assertThat("Should return failure for null email", result.isFailure(), is(true));
            assertThat(result.getFailure(), equalTo(DecisionError.INVALID_USER_CONTEXT));
        }

        @Test
        void shouldReturnInvalidUserContext_whenJourneyTypeIsNull() {
            // When
            var result = permissionDecisionManager.canReceivePassword(null, userPermissionContext);

            // Then
            assertThat("Should return failure for null journey type", result.isFailure(), is(true));
            assertThat(result.getFailure(), equalTo(DecisionError.INVALID_USER_CONTEXT));
        }

        @Test
        void shouldReturnStorageServiceError_whenCodeStorageServiceThrowsException() {
            // Given
            when(codeStorageService.isBlockedForEmail(
                            TEST_EMAIL,
                            CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX
                                    + JourneyType.PASSWORD_RESET))
                    .thenThrow(new RuntimeException("Storage error"));

            // When
            var result =
                    permissionDecisionManager.canReceivePassword(
                            JourneyType.SIGN_IN, userPermissionContext);

            // Then
            assertThat("Should return failure for storage exception", result.isFailure(), is(true));
            assertThat(result.getFailure(), equalTo(DecisionError.STORAGE_SERVICE_ERROR));
        }
    }

    @Nested
    class ActiveAuthAppLockouts {
        @Test
        void shouldReturnEmptyList_whenNoLockoutsActive() {
            // Given
            when(codeStorageService.getMfaCodeBlockTimeToLive(
                            TEST_EMAIL, MFAMethodType.AUTH_APP, JourneyType.SIGN_IN))
                    .thenReturn(0L);
            when(codeStorageService.getMfaCodeBlockTimeToLive(
                            TEST_EMAIL, MFAMethodType.AUTH_APP, JourneyType.PASSWORD_RESET_MFA))
                    .thenReturn(0L);

            // When
            var result = permissionDecisionManager.getActiveAuthAppLockouts(userPermissionContext);

            // Then
            assertThat("Should return successful result", result.isSuccess(), is(true));
            assertThat(
                    "Should return empty list when no lockouts", result.getSuccess(), hasSize(0));
        }

        @Test
        void shouldReturnActiveLockouts_whenLockoutsExist() {
            // Given
            when(codeStorageService.getMfaCodeBlockTimeToLive(
                            TEST_EMAIL, MFAMethodType.AUTH_APP, JourneyType.SIGN_IN))
                    .thenReturn(300L);
            when(codeStorageService.getMfaCodeBlockTimeToLive(
                            TEST_EMAIL, MFAMethodType.AUTH_APP, JourneyType.PASSWORD_RESET_MFA))
                    .thenReturn(0L);

            // When
            var result = permissionDecisionManager.getActiveAuthAppLockouts(userPermissionContext);

            // Then
            assertThat("Should return successful result", result.isSuccess(), is(true));
            var lockouts = result.getSuccess();
            assertThat("Should return one active lockout", lockouts, hasSize(1));
            var lockout = lockouts.get(0);
            assertThat(lockout.lockType(), equalTo("codeBlock"));
            assertThat(lockout.mfaMethodType(), equalTo(MFAMethodType.AUTH_APP));
            assertThat(lockout.lockTTL(), equalTo(300L));
            assertThat(lockout.journeyType(), equalTo(JourneyType.SIGN_IN));
        }

        @Test
        void shouldReturnMultipleLockouts_whenBothJourneyTypesLocked() {
            // Given
            when(codeStorageService.getMfaCodeBlockTimeToLive(
                            TEST_EMAIL, MFAMethodType.AUTH_APP, JourneyType.SIGN_IN))
                    .thenReturn(300L);
            when(codeStorageService.getMfaCodeBlockTimeToLive(
                            TEST_EMAIL, MFAMethodType.AUTH_APP, JourneyType.PASSWORD_RESET_MFA))
                    .thenReturn(600L);

            // When
            var result = permissionDecisionManager.getActiveAuthAppLockouts(userPermissionContext);

            // Then
            assertThat("Should return successful result", result.isSuccess(), is(true));
            assertThat("Should return two active lockouts", result.getSuccess(), hasSize(2));
        }
    }
}
