package uk.gov.di.accountmanagement.services;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.RedisConnectionService;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.entity.NotificationType.VERIFY_EMAIL;

class CodeStorageServiceTest {

    private static final String TEST_EMAIL = "test@test.com";
    private static final String CODE = "123456";
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private final CodeStorageService codeStorageService =
            new CodeStorageService(redisConnectionService);
    private static final String REDIS_EMAIL_KEY =
            "email-code:f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a";
    private static final long CODE_EXPIRY_TIME = 900;

    @Test
    public void shouldCallRedisWithValidEmailCodeAndHashedEmail() {
        codeStorageService.saveOtpCode(TEST_EMAIL, CODE, CODE_EXPIRY_TIME, VERIFY_EMAIL);

        verify(redisConnectionService).saveWithExpiry(REDIS_EMAIL_KEY, CODE, CODE_EXPIRY_TIME);
    }

    @Test
    public void shouldCallRedisToDeleteEmailCodeWithHashedEmail() {
        codeStorageService.deleteOtpCode(TEST_EMAIL, VERIFY_EMAIL);

        verify(redisConnectionService).deleteValue(REDIS_EMAIL_KEY);
    }

    @Test
    public void shouldSuccessfullyValidateOtpCodeAndDelete() {
        when(redisConnectionService.getValue(REDIS_EMAIL_KEY)).thenReturn(CODE);

        assertTrue(codeStorageService.isValidOtpCode(TEST_EMAIL, CODE, VERIFY_EMAIL));
        verify(redisConnectionService).deleteValue(REDIS_EMAIL_KEY);
    }

    @Test
    public void shouldReturnFalseWhenOtpCodeNotFound() {
        when(redisConnectionService.getValue(REDIS_EMAIL_KEY)).thenReturn(null);

        assertFalse(codeStorageService.isValidOtpCode(TEST_EMAIL, CODE, VERIFY_EMAIL));
        verify(redisConnectionService, times(0)).deleteValue(REDIS_EMAIL_KEY);
    }

    @Test
    public void shouldReturnFalseWhenOtpFoundButCodeDoesNotMatch() {
        when(redisConnectionService.getValue(REDIS_EMAIL_KEY)).thenReturn(CODE);

        assertFalse(codeStorageService.isValidOtpCode(TEST_EMAIL, "1234", VERIFY_EMAIL));
        verify(redisConnectionService, times(0)).deleteValue(REDIS_EMAIL_KEY);
    }
}
