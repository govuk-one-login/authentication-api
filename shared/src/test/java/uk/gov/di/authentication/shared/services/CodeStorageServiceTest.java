package uk.gov.di.authentication.shared.services;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.helpers.IdGenerator;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.services.CodeStorageService.PASSWORD_RESET_BLOCKED_KEY_PREFIX;

class CodeStorageServiceTest {

    private static final String TEST_EMAIL = "test@test.com";
    private static final String CODE = "123456";
    private static final String SUBJECT = "some-subject";
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private final CodeStorageService codeStorageService =
            new CodeStorageService(redisConnectionService);
    private static final String REDIS_EMAIL_KEY =
            "email-code:f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a";
    private static final String REDIS_INCORRECT_PASSWORDS_KEY =
            "multiple-incorrect-passwords:f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a";
    private static final String REDIS_INCORRECT_MFA_CODES_KEY =
            "multiple-incorrect-mfa-codes:f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a";
    private static final String REDIS_PHONE_NUMBER_KEY =
            "phone-number-code:f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a";
    private static final String REDIS_MFA_KEY =
            "mfa-code:f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a";
    private static final String REDIS_BLOCKED_KEY =
            "code-blocked:f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a";
    private static final String REDIS_BLOCKED_REQUEST_KEY =
            "code-request-blocked:f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a";
    private static final String REDIS_BLOCKED_PASSWORD_RESET_KEY =
            "password-reset-blocked:f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a";
    private static final String RESET_PASSWORD_KEY = "reset-password-code:" + CODE;
    private static final long CODE_EXPIRY_TIME = 900;
    private static final long AUTH_CODE_EXPIRY_TIME = 300;
    private static final String CODE_BLOCKED_VALUE = "blocked";

    @Test
    void shouldCallRedisWithValidEmailCodeAndHashedEmail() {
        codeStorageService.saveOtpCode(TEST_EMAIL, CODE, CODE_EXPIRY_TIME, VERIFY_EMAIL);

        verify(redisConnectionService).saveWithExpiry(REDIS_EMAIL_KEY, CODE, CODE_EXPIRY_TIME);
    }

    @Test
    void shouldCallRedisWithValidResetPasswordCodeAndSubject() {
        codeStorageService.savePasswordResetCode(SUBJECT, CODE, CODE_EXPIRY_TIME, RESET_PASSWORD);

        verify(redisConnectionService)
                .saveWithExpiry(RESET_PASSWORD_KEY, SUBJECT, CODE_EXPIRY_TIME);
    }

    @Test
    void shouldRetrievePasswordResetSubject() {
        when(redisConnectionService.getValue(RESET_PASSWORD_KEY)).thenReturn(SUBJECT);

        String subject = codeStorageService.getSubjectWithPasswordResetCode(CODE).get();

        assertThat(subject, is(SUBJECT));
    }

    @Test
    void shouldCallRedisToDeletePasswordResetSubject() {
        codeStorageService.deleteSubjectWithPasswordResetCode(CODE);

        verify(redisConnectionService).deleteValue(RESET_PASSWORD_KEY);
    }

    @Test
    void shouldRetrieveEmailCode() {
        when(redisConnectionService.getValue(REDIS_EMAIL_KEY)).thenReturn(CODE);

        String codeForEmail = codeStorageService.getOtpCode(TEST_EMAIL, VERIFY_EMAIL).get();

        assertThat(codeForEmail, is(CODE));
    }

    @Test
    void shouldReturnEmptyOptionalIfEmailCodeDoesNotExist() {
        when(redisConnectionService.getValue(REDIS_EMAIL_KEY)).thenReturn(null);

        assertTrue(codeStorageService.getOtpCode(TEST_EMAIL, VERIFY_EMAIL).isEmpty());
    }

    @Test
    void shouldCallRedisToDeleteEmailCodeWithHashedEmail() {
        codeStorageService.deleteOtpCode(TEST_EMAIL, VERIFY_EMAIL);

        verify(redisConnectionService).deleteValue(REDIS_EMAIL_KEY);
    }

    @Test
    void shouldCallRedisWithValidPhoneNumberCodeAndHashedEmailAddress() {
        codeStorageService.saveOtpCode(
                TEST_EMAIL, CODE, CODE_EXPIRY_TIME, NotificationType.VERIFY_PHONE_NUMBER);

        verify(redisConnectionService)
                .saveWithExpiry(REDIS_PHONE_NUMBER_KEY, CODE, CODE_EXPIRY_TIME);
    }

    @Test
    void shouldRetrievePhoneNumberCode() {
        when(redisConnectionService.getValue(REDIS_PHONE_NUMBER_KEY)).thenReturn(CODE);

        String codeForEmail =
                codeStorageService
                        .getOtpCode(TEST_EMAIL, NotificationType.VERIFY_PHONE_NUMBER)
                        .get();

        assertThat(codeForEmail, is(CODE));
    }

    @Test
    void shouldReturnEmptyOptionalIfPhoneNumberCodeDoesNotExist() {
        when(redisConnectionService.getValue(REDIS_PHONE_NUMBER_KEY)).thenReturn(null);

        assertTrue(
                codeStorageService
                        .getOtpCode(TEST_EMAIL, NotificationType.VERIFY_PHONE_NUMBER)
                        .isEmpty());
    }

    @Test
    void shouldCallRedisToDeletePhoneNumberCodeWithHashedEmail() {
        codeStorageService.deleteOtpCode(TEST_EMAIL, NotificationType.VERIFY_PHONE_NUMBER);

        verify(redisConnectionService).deleteValue(REDIS_PHONE_NUMBER_KEY);
    }

    @Test
    void shouldSaveToRedisWhenCodeIsBlockedForEmail() {
        codeStorageService.saveBlockedForEmail(
                TEST_EMAIL, CODE_BLOCKED_KEY_PREFIX, CODE_EXPIRY_TIME);

        verify(redisConnectionService)
                .saveWithExpiry(REDIS_BLOCKED_KEY, CODE_BLOCKED_VALUE, CODE_EXPIRY_TIME);
    }

    @Test
    void shouldSaveToRedisWhenCodeRequestIsBlockedForEmail() {
        codeStorageService.saveBlockedForEmail(
                TEST_EMAIL, CODE_REQUEST_BLOCKED_KEY_PREFIX, CODE_EXPIRY_TIME);

        verify(redisConnectionService)
                .saveWithExpiry(REDIS_BLOCKED_REQUEST_KEY, CODE_BLOCKED_VALUE, CODE_EXPIRY_TIME);
    }

    @Test
    void shouldSaveToRedisWhenPasswordResetIsBlockedForEmail() {
        codeStorageService.saveBlockedForEmail(
                TEST_EMAIL, PASSWORD_RESET_BLOCKED_KEY_PREFIX, CODE_EXPIRY_TIME);

        verify(redisConnectionService)
                .saveWithExpiry(
                        REDIS_BLOCKED_PASSWORD_RESET_KEY, CODE_BLOCKED_VALUE, CODE_EXPIRY_TIME);
    }

    @Test
    void shouldRetrieveEmailWhenCodeIsBlocked() {
        when(redisConnectionService.getValue(REDIS_BLOCKED_KEY)).thenReturn(CODE_BLOCKED_VALUE);

        assertTrue(codeStorageService.isBlockedForEmail(TEST_EMAIL, CODE_BLOCKED_KEY_PREFIX));
    }

    @Test
    void shouldRetrieveEmailWhenCodeRequestIsBlocked() {
        when(redisConnectionService.getValue(REDIS_BLOCKED_REQUEST_KEY))
                .thenReturn(CODE_BLOCKED_VALUE);

        assertTrue(
                codeStorageService.isBlockedForEmail(TEST_EMAIL, CODE_REQUEST_BLOCKED_KEY_PREFIX));
    }

    @Test
    void shouldRetrieveEmailWhenPasswordResetIsBlocked() {
        when(redisConnectionService.getValue(REDIS_BLOCKED_PASSWORD_RESET_KEY))
                .thenReturn(CODE_BLOCKED_VALUE);

        assertTrue(
                codeStorageService.isBlockedForEmail(
                        TEST_EMAIL, PASSWORD_RESET_BLOCKED_KEY_PREFIX));
    }

    @Test
    void shouldReturnEmptyOptionalWhenCodeIsNotBlockedForSession() {
        when(redisConnectionService.getValue(REDIS_BLOCKED_KEY)).thenReturn(null);

        assertFalse(codeStorageService.isBlockedForEmail(TEST_EMAIL, CODE_BLOCKED_KEY_PREFIX));
    }

    @Test
    void shouldReturnEmptyOptionalWhenCodeRequestIsNotBlockedForSession() {
        when(redisConnectionService.getValue(REDIS_BLOCKED_REQUEST_KEY)).thenReturn(null);

        assertFalse(
                codeStorageService.isBlockedForEmail(TEST_EMAIL, CODE_REQUEST_BLOCKED_KEY_PREFIX));
    }

    @Test
    void shouldReturnEmptyOptionalWhenPasswordResetIsNotBlockedForSession() {
        when(redisConnectionService.getValue(REDIS_BLOCKED_PASSWORD_RESET_KEY)).thenReturn(null);

        assertFalse(
                codeStorageService.isBlockedForEmail(
                        TEST_EMAIL, PASSWORD_RESET_BLOCKED_KEY_PREFIX));
    }

    @Test
    void shouldCallRedisWithValidMfaCodeAndHashedEmail() {
        codeStorageService.saveOtpCode(
                TEST_EMAIL, CODE, CODE_EXPIRY_TIME, NotificationType.MFA_SMS);

        verify(redisConnectionService).saveWithExpiry(REDIS_MFA_KEY, CODE, CODE_EXPIRY_TIME);
    }

    @Test
    void shouldCallRedisWithAuthorizationCode() {
        String authorizationCode = new AuthorizationCode().getValue();
        String clientSessionId = IdGenerator.generate();
        codeStorageService.saveAuthorizationCode(
                authorizationCode, clientSessionId, AUTH_CODE_EXPIRY_TIME);

        verify(redisConnectionService)
                .saveWithExpiry(authorizationCode, clientSessionId, AUTH_CODE_EXPIRY_TIME);
    }

    @Test
    void shouldReturn0WhenThereHaveBeenNoIncorrectMfaCodeAttempts() {
        when(redisConnectionService.getValue(REDIS_INCORRECT_MFA_CODES_KEY)).thenReturn(null);
        assertThat(codeStorageService.getIncorrectMfaCodeAttemptsCount(TEST_EMAIL), equalTo(0));
    }

    @Test
    void shouldReturnNumberOfIncorrectMfaCodeAttempts() {
        when(redisConnectionService.getValue(REDIS_INCORRECT_MFA_CODES_KEY))
                .thenReturn(String.valueOf(4));
        assertThat(codeStorageService.getIncorrectMfaCodeAttemptsCount(TEST_EMAIL), equalTo(4));
    }

    @Test
    void shouldCreateCountInRedisWhenThereHasBeenNoPreviousIncorrectMfaCodeAttempt() {
        when(redisConnectionService.getValue(REDIS_INCORRECT_MFA_CODES_KEY)).thenReturn(null);
        codeStorageService.increaseIncorrectMfaCodeAttemptsCount(TEST_EMAIL);

        verify(redisConnectionService)
                .saveWithExpiry(REDIS_INCORRECT_MFA_CODES_KEY, String.valueOf(1), CODE_EXPIRY_TIME);
    }

    @Test
    void shouldIncrementCountWhenThereHasBeenPreviousIncorrectMfaCodeAttempt() {
        when(redisConnectionService.getValue(REDIS_INCORRECT_MFA_CODES_KEY))
                .thenReturn(String.valueOf(3));
        codeStorageService.increaseIncorrectMfaCodeAttemptsCount(TEST_EMAIL);

        verify(redisConnectionService)
                .saveWithExpiry(REDIS_INCORRECT_MFA_CODES_KEY, String.valueOf(4), CODE_EXPIRY_TIME);
    }

    @Test
    void shouldCallRedisToDeleteIncorrectMfaCodeAttemptCount() {
        codeStorageService.deleteIncorrectMfaCodeAttemptsCount(TEST_EMAIL);

        verify(redisConnectionService).deleteValue(REDIS_INCORRECT_MFA_CODES_KEY);
    }

    @Test
    void shouldReturn0WhenThereHasBeenNoInvalidPasswordAttempts() {
        when(redisConnectionService.getValue(REDIS_INCORRECT_PASSWORDS_KEY)).thenReturn(null);
        assertThat(codeStorageService.getIncorrectPasswordCount(TEST_EMAIL), equalTo(0));
    }

    @Test
    void shouldReturnNumberOfInvalidPasswordAttempts() {
        when(redisConnectionService.getValue(REDIS_INCORRECT_PASSWORDS_KEY))
                .thenReturn(String.valueOf(4));
        assertThat(codeStorageService.getIncorrectPasswordCount(TEST_EMAIL), equalTo(4));
    }

    @Test
    void shouldCreateCountInRedisWhenThereHasBeenNoPreviousIncorrectPasswordAttempt() {
        when(redisConnectionService.getValue(REDIS_INCORRECT_PASSWORDS_KEY)).thenReturn(null);
        codeStorageService.increaseIncorrectPasswordCount(TEST_EMAIL);

        verify(redisConnectionService)
                .saveWithExpiry(REDIS_INCORRECT_PASSWORDS_KEY, String.valueOf(1), CODE_EXPIRY_TIME);
    }

    @Test
    void shouldIncrementCountWhenThereHasBeenPreviousIncorrectPasswordAttempts() {
        when(redisConnectionService.getValue(REDIS_INCORRECT_PASSWORDS_KEY))
                .thenReturn(String.valueOf(3));
        codeStorageService.increaseIncorrectPasswordCount(TEST_EMAIL);

        verify(redisConnectionService)
                .saveWithExpiry(REDIS_INCORRECT_PASSWORDS_KEY, String.valueOf(4), CODE_EXPIRY_TIME);
    }

    @Test
    void shouldCallRedisToDeleteIncorrectPasswordCount() {
        codeStorageService.deleteIncorrectPasswordCount(TEST_EMAIL);

        verify(redisConnectionService).deleteValue(REDIS_INCORRECT_PASSWORDS_KEY);
    }
}
