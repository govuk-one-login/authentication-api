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

class CodeStorageServiceTest {

    private static final String TEST_EMAIL = "test@test.com";
    private static final String CODE = "123456";
    private static final String SUBJECT = "some-subject";
    private static final String SESSION_ID = "session-id-1234";
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private final CodeStorageService codeStorageService =
            new CodeStorageService(redisConnectionService);
    private static final String REDIS_EMAIL_KEY =
            "email-code:f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a";
    private static final String REDIS_INCORRECT_PASSWORDS_KEY =
            "multiple-incorrect-passwords:f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a";
    private static final String REDIS_PHONE_NUMBER_KEY =
            "phone-number-code:f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a";
    private static final String REDIS_MFA_KEY =
            "mfa-code:f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a";
    private static final String REDIS_BLOCKED_KEY =
            "code-blocked:f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a"
                    + SESSION_ID;
    private static final String RESET_PASSWORD_KEY = "reset-password-code:" + CODE;
    private static final long CODE_EXPIRY_TIME = 900;
    private static final long AUTH_CODE_EXPIRY_TIME = 300;
    private static final String CODE_BLOCKED_VALUE = "blocked";

    @Test
    public void shouldCallRedisWithValidEmailCodeAndHashedEmail() {
        codeStorageService.saveOtpCode(TEST_EMAIL, CODE, CODE_EXPIRY_TIME, VERIFY_EMAIL);

        verify(redisConnectionService).saveWithExpiry(REDIS_EMAIL_KEY, CODE, CODE_EXPIRY_TIME);
    }

    @Test
    public void shouldCallRedisWithValidResetPasswordCodeAndSubject() {
        codeStorageService.savePasswordResetCode(SUBJECT, CODE, CODE_EXPIRY_TIME, RESET_PASSWORD);

        verify(redisConnectionService)
                .saveWithExpiry(RESET_PASSWORD_KEY, SUBJECT, CODE_EXPIRY_TIME);
    }

    @Test
    public void shouldRetrievePasswordResetSubject() {
        when(redisConnectionService.getValue(RESET_PASSWORD_KEY)).thenReturn(SUBJECT);

        String subject = codeStorageService.getSubjectWithPasswordResetCode(CODE).get();

        assertThat(subject, is(SUBJECT));
    }

    @Test
    public void shouldCallRedisToDeletePasswordResetSubject() {
        codeStorageService.deleteSubjectWithPasswordResetCode(CODE);

        verify(redisConnectionService).deleteValue(RESET_PASSWORD_KEY);
    }

    @Test
    public void shouldRetrieveEmailCode() {
        when(redisConnectionService.getValue(REDIS_EMAIL_KEY)).thenReturn(CODE);

        String codeForEmail = codeStorageService.getOtpCode(TEST_EMAIL, VERIFY_EMAIL).get();

        assertThat(codeForEmail, is(CODE));
    }

    @Test
    public void shouldReturnEmptyOptionalIfEmailCodeDoesNotExist() {
        when(redisConnectionService.getValue(REDIS_EMAIL_KEY)).thenReturn(null);

        assertTrue(codeStorageService.getOtpCode(TEST_EMAIL, VERIFY_EMAIL).isEmpty());
    }

    @Test
    public void shouldCallRedisToDeleteEmailCodeWithHashedEmail() {
        codeStorageService.deleteOtpCode(TEST_EMAIL, VERIFY_EMAIL);

        verify(redisConnectionService).deleteValue(REDIS_EMAIL_KEY);
    }

    @Test
    public void shouldCallRedisWithValidPhoneNumberCodeAndHashedEmailAddress() {
        codeStorageService.saveOtpCode(
                TEST_EMAIL, CODE, CODE_EXPIRY_TIME, NotificationType.VERIFY_PHONE_NUMBER);

        verify(redisConnectionService)
                .saveWithExpiry(REDIS_PHONE_NUMBER_KEY, CODE, CODE_EXPIRY_TIME);
    }

    @Test
    public void shouldRetrievePhoneNumberCode() {
        when(redisConnectionService.getValue(REDIS_PHONE_NUMBER_KEY)).thenReturn(CODE);

        String codeForEmail =
                codeStorageService
                        .getOtpCode(TEST_EMAIL, NotificationType.VERIFY_PHONE_NUMBER)
                        .get();

        assertThat(codeForEmail, is(CODE));
    }

    @Test
    public void shouldReturnEmptyOptionalIfPhoneNumberCodeDoesNotExist() {
        when(redisConnectionService.getValue(REDIS_PHONE_NUMBER_KEY)).thenReturn(null);

        assertTrue(
                codeStorageService
                        .getOtpCode(TEST_EMAIL, NotificationType.VERIFY_PHONE_NUMBER)
                        .isEmpty());
    }

    @Test
    public void shouldCallRedisToDeletePhoneNumberCodeWithHashedEmail() {
        codeStorageService.deleteOtpCode(TEST_EMAIL, NotificationType.VERIFY_PHONE_NUMBER);

        verify(redisConnectionService).deleteValue(REDIS_PHONE_NUMBER_KEY);
    }

    @Test
    public void shouldSaveToRedisWhenCodeIsBlockedForSession() {
        codeStorageService.saveCodeBlockedForSession(TEST_EMAIL, SESSION_ID, CODE_EXPIRY_TIME);

        verify(redisConnectionService)
                .saveWithExpiry(REDIS_BLOCKED_KEY, CODE_BLOCKED_VALUE, CODE_EXPIRY_TIME);
    }

    @Test
    public void shouldRetrieveSessionIdWhenCodeIsBlocked() {
        when(redisConnectionService.getValue(REDIS_BLOCKED_KEY)).thenReturn(CODE_BLOCKED_VALUE);

        assertTrue(codeStorageService.isCodeBlockedForSession(TEST_EMAIL, SESSION_ID));
    }

    @Test
    public void shouldReturnEmptyOptionalWhenCodeIsNotBlockedForSession() {
        when(redisConnectionService.getValue(REDIS_BLOCKED_KEY)).thenReturn(null);

        assertFalse(codeStorageService.isCodeBlockedForSession(TEST_EMAIL, SESSION_ID));
    }

    @Test
    public void shouldCallRedisWithValidMfaCodeAndHashedEmail() {
        codeStorageService.saveOtpCode(
                TEST_EMAIL, CODE, CODE_EXPIRY_TIME, NotificationType.MFA_SMS);

        verify(redisConnectionService).saveWithExpiry(REDIS_MFA_KEY, CODE, CODE_EXPIRY_TIME);
    }

    @Test
    public void shouldCallRedisWithAuthorizationCode() {
        String authorizationCode = new AuthorizationCode().getValue();
        String clientSessionId = IdGenerator.generate();
        codeStorageService.saveAuthorizationCode(
                authorizationCode, clientSessionId, AUTH_CODE_EXPIRY_TIME);

        verify(redisConnectionService)
                .saveWithExpiry(authorizationCode, clientSessionId, AUTH_CODE_EXPIRY_TIME);
    }

    @Test
    public void shouldReturn0WhenThereHasBeenNoInvalidPasswordAttempts() {
        when(redisConnectionService.getValue(REDIS_INCORRECT_PASSWORDS_KEY)).thenReturn(null);
        assertThat(codeStorageService.getIncorrectPasswordCount(TEST_EMAIL), equalTo(0));
    }

    @Test
    public void shouldReturnNumberOfInvalidPasswordAttempts() {
        when(redisConnectionService.getValue(REDIS_INCORRECT_PASSWORDS_KEY))
                .thenReturn(String.valueOf(4));
        assertThat(codeStorageService.getIncorrectPasswordCount(TEST_EMAIL), equalTo(4));
    }

    @Test
    public void shouldCreateCountInRedisWhenThereHasBeenNoPreviousIncorrectPasswordAttempt() {
        when(redisConnectionService.getValue(REDIS_INCORRECT_PASSWORDS_KEY)).thenReturn(null);
        codeStorageService.increaseIncorrectPasswordCount(TEST_EMAIL);

        verify(redisConnectionService)
                .saveWithExpiry(REDIS_INCORRECT_PASSWORDS_KEY, String.valueOf(1), CODE_EXPIRY_TIME);
    }

    @Test
    public void shouldIncrementCountWhenThereHasBeenPreviousIncorrectPasswordAttempts() {
        when(redisConnectionService.getValue(REDIS_INCORRECT_PASSWORDS_KEY))
                .thenReturn(String.valueOf(3));
        codeStorageService.increaseIncorrectPasswordCount(TEST_EMAIL);

        verify(redisConnectionService)
                .saveWithExpiry(REDIS_INCORRECT_PASSWORDS_KEY, String.valueOf(4), CODE_EXPIRY_TIME);
    }

    @Test
    public void shouldCallRedisToDeleteIncorrectPasswordCount() {
        codeStorageService.deleteIncorrectPasswordCount(TEST_EMAIL);

        verify(redisConnectionService).deleteValue(REDIS_INCORRECT_PASSWORDS_KEY);
    }
}
