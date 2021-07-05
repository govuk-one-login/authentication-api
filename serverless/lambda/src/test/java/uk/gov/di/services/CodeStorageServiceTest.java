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
    private static final String REDIS_EMAIL_KEY =
            "email-code:f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a";
    private static final String REDIS_PHONE_NUMBER_KEY =
            "phone-number-code:f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a";
    private static final long CODE_EXPIRY_TIME = 900;

    @Test
    public void shouldCallRedisWithValidEmailCodeAndHashedEmail() {
        String code = "123456";
        codeStorageService.saveEmailCode("test@test.com", "123456", CODE_EXPIRY_TIME);

        verify(redisConnectionService).saveWithExpiry(REDIS_EMAIL_KEY, code, CODE_EXPIRY_TIME);
    }

    @Test
    public void shouldRetrieveEmailCode() {
        when(redisConnectionService.getValue(REDIS_EMAIL_KEY)).thenReturn("123456");

        String codeForEmail = codeStorageService.getCodeForEmail("test@test.com").get();

        assertThat(codeForEmail, is("123456"));
    }

    @Test
    public void shouldReturnEmptyOptionalIfEmailCodeDoesNotExist() {
        when(redisConnectionService.getValue(REDIS_EMAIL_KEY)).thenReturn(null);

        assertTrue(codeStorageService.getCodeForEmail("test@test.com").isEmpty());
    }

    @Test
    public void shouldCallRedisToDeleteEmailCodeWithHashedEmail() {
        codeStorageService.deleteCodeForEmail("test@test.com");

        verify(redisConnectionService).deleteValue(REDIS_EMAIL_KEY);
    }

    @Test
    public void shouldCallRedisWithValidPhoneNumberCodeAndHashedEmailAddress() {
        String code = "123456";
        codeStorageService.savePhoneNumberCode("test@test.com", "123456", CODE_EXPIRY_TIME);

        verify(redisConnectionService)
                .saveWithExpiry(REDIS_PHONE_NUMBER_KEY, code, CODE_EXPIRY_TIME);
    }

    @Test
    public void shouldRetrievePhoneNumberCode() {
        when(redisConnectionService.getValue(REDIS_PHONE_NUMBER_KEY)).thenReturn("123456");

        String codeForEmail = codeStorageService.getPhoneNumberCode("test@test.com").get();

        assertThat(codeForEmail, is("123456"));
    }

    @Test
    public void shouldReturnEmptyOptionalIfPhoneNumberCodeDoesNotExist() {
        when(redisConnectionService.getValue(REDIS_PHONE_NUMBER_KEY)).thenReturn(null);

        assertTrue(codeStorageService.getPhoneNumberCode("test@test.com").isEmpty());
    }

    @Test
    public void shouldCallRedisToDeletePhoneNumberCodeWithHashedEmail() {
        codeStorageService.deletePhoneNumberCode("test@test.com");

        verify(redisConnectionService).deleteValue(REDIS_PHONE_NUMBER_KEY);
    }
}
