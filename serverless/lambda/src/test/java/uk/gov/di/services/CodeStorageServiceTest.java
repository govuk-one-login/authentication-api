package uk.gov.di.services;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CodeStorageServiceTest {

    public static final String TEST_EMAIL = "test@test.com";
    public static final String CODE = "123456";
    public static final String SESSION_ID = "session-id-1234";
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private final CodeStorageService codeStorageService =
            new CodeStorageService(redisConnectionService);
    private static final String REDIS_EMAIL_KEY =
            "email-code:f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a";
    private static final String REDIS_PHONE_NUMBER_KEY =
            "phone-number-code:f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a";
    private static final String REDIS_BLOCKED_KEY =
            "code-blocked:f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a"
                    + SESSION_ID;
    private static final long CODE_EXPIRY_TIME = 900;
    private static final String CODE_BLOCKED_VALUE = "blocked";

    @Test
    public void shouldCallRedisWithValidEmailCodeAndHashedEmail() {
        codeStorageService.saveEmailCode(TEST_EMAIL, CODE, CODE_EXPIRY_TIME);

        verify(redisConnectionService).saveWithExpiry(REDIS_EMAIL_KEY, CODE, CODE_EXPIRY_TIME);
    }

    @Test
    public void shouldRetrieveEmailCode() {
        when(redisConnectionService.getValue(REDIS_EMAIL_KEY)).thenReturn(CODE);

        String codeForEmail = codeStorageService.getCodeForEmail(TEST_EMAIL).get();

        assertThat(codeForEmail, is(CODE));
    }

    @Test
    public void shouldReturnEmptyOptionalIfEmailCodeDoesNotExist() {
        when(redisConnectionService.getValue(REDIS_EMAIL_KEY)).thenReturn(null);

        assertTrue(codeStorageService.getCodeForEmail(TEST_EMAIL).isEmpty());
    }

    @Test
    public void shouldCallRedisToDeleteEmailCodeWithHashedEmail() {
        codeStorageService.deleteCodeForEmail(TEST_EMAIL);

        verify(redisConnectionService).deleteValue(REDIS_EMAIL_KEY);
    }

    @Test
    public void shouldCallRedisWithValidPhoneNumberCodeAndHashedEmailAddress() {
        codeStorageService.savePhoneNumberCode(TEST_EMAIL, CODE, CODE_EXPIRY_TIME);

        verify(redisConnectionService)
                .saveWithExpiry(REDIS_PHONE_NUMBER_KEY, CODE, CODE_EXPIRY_TIME);
    }

    @Test
    public void shouldRetrievePhoneNumberCode() {
        when(redisConnectionService.getValue(REDIS_PHONE_NUMBER_KEY)).thenReturn(CODE);

        String codeForEmail = codeStorageService.getPhoneNumberCode(TEST_EMAIL).get();

        assertThat(codeForEmail, is(CODE));
    }

    @Test
    public void shouldReturnEmptyOptionalIfPhoneNumberCodeDoesNotExist() {
        when(redisConnectionService.getValue(REDIS_PHONE_NUMBER_KEY)).thenReturn(null);

        assertTrue(codeStorageService.getPhoneNumberCode(TEST_EMAIL).isEmpty());
    }

    @Test
    public void shouldCallRedisToDeletePhoneNumberCodeWithHashedEmail() {
        codeStorageService.deletePhoneNumberCode(TEST_EMAIL);

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

        assertThat(
                codeStorageService.getCodeBlockedForSession(TEST_EMAIL, SESSION_ID),
                is(Optional.of(CODE_BLOCKED_VALUE)));
    }

    @Test
    public void shouldReturnEmptyOptionalWhenCodeIsNotBlockedForSession() {
        when(redisConnectionService.getValue(REDIS_BLOCKED_KEY)).thenReturn(null);

        assertTrue(codeStorageService.getCodeBlockedForSession(TEST_EMAIL, SESSION_ID).isEmpty());
    }
}
