package uk.gov.di.services;

import org.junit.jupiter.api.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class CodeStorageServiceTest {

    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private final CodeStorageService codeStorageService =
            new CodeStorageService(redisConnectionService);
    private static final String EMAIL_KEY_PREFIX = "email-code:";
    private static final long CODE_EXPIRY_TIME = 900l;

    @Test
    public void shouldCallRedisWithValidCodeAndHashedEmail() {
        String code = "123456";
        codeStorageService.saveEmailCode("test@test.com", "123456");

        String redisEmailKey =
                EMAIL_KEY_PREFIX
                        + "f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a";

        verify(redisConnectionService).saveCodeWithExpiry(redisEmailKey, code, CODE_EXPIRY_TIME);
    }
}
