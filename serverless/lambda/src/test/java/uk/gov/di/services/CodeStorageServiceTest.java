package uk.gov.di.services;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CodeStorageServiceTest {

    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private final CodeStorageService codeStorageService =
            new CodeStorageService(redisConnectionService);
    private static final String EMAIL_KEY_PREFIX = "email-code:";
    private static final String PHONE_NUMBER_KEY_PREFIX = "phone-number-code:";
    private static final long CODE_EXPIRY_TIME = 900;

    @Test
    public void shouldCallRedisWithValidCodeAndHashedEmail() {
        String code = "123456";
        codeStorageService.saveEmailCode("test@test.com", "123456", CODE_EXPIRY_TIME);

        String redisEmailKey =
                EMAIL_KEY_PREFIX
                        + "f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a";

        verify(redisConnectionService).saveWithExpiry(redisEmailKey, code, CODE_EXPIRY_TIME);
    }

    @Test
    public void shouldRetrieveCodeForEmail() {
        when(redisConnectionService.getValue(
                        "email-code:f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a"))
                .thenReturn("123456");

        String codeForEmail = codeStorageService.getCodeForEmail("test@test.com").get();

        assertThat(codeForEmail, is("123456"));
    }

    @Test
    public void shouldReturnEmptyOptionalIfEmailCodeDoesNotExist() {
        when(redisConnectionService.getValue(
                        "email-code:f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a"))
                .thenReturn(null);

        assertTrue(codeStorageService.getCodeForEmail("test@test.com").isEmpty());
    }

    @Test
    public void shouldCallRedisToDeleteCodeWithHashedEmail() {
        codeStorageService.deleteCodeForEmail("test@test.com");

        verify(redisConnectionService)
                .deleteValue(
                        "email-code:f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a");
    }

    @Test
    public void shouldCallRedisWithValidCodeAndHashedPhoneNumber() {
        String code = "123456";
        codeStorageService.savePhoneNumberCode("01234567891", "123456", CODE_EXPIRY_TIME);

        String redisEmailKey =
                PHONE_NUMBER_KEY_PREFIX
                        + "2edb6e72d5aaf346259b36a79bdb8a6cde1d7e537b92e6a2c60ffbb9ce93a4db";

        verify(redisConnectionService).saveWithExpiry(redisEmailKey, code, CODE_EXPIRY_TIME);
    }
}
