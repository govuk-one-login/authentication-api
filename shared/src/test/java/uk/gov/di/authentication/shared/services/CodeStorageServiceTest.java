package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;

class CodeStorageServiceTest {

    private static final String TEST_EMAIL = "test@test.com";
    private static final String TEST_EMAIL_HASH =
            "f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a";
    private static final String CODE = "123456";
    private static final long CODE_EXPIRY_TIME = 900;
    private static final long PW_CODE_EXPIRY_TIME = 900;
    private static final long ACCOUNT_CREATION_CODE_EXPIRY_TIME = 3600;
    private static final String CODE_BLOCKED_VALUE = "blocked";
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);

    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);
    private final CodeStorageService codeStorageService =
            new CodeStorageService(configurationService, redisConnectionService);

    enum RedisKeys {
        INCORRECT_MFA_COUNTER("multiple-incorrect-mfa-codes:"),
        INCORRECT_PASSWORD_COUNTER("multiple-incorrect-passwords:"),
        EMAIL_OTP_CODE("email-code:"),
        PHONE_OTP_CODE("phone-number-code:"),
        RESET_PASSWORD_KEY("reset-password-code:"),
        MFA_CODE("mfa-code:"),
        CODE_BLOCK("code-blocked:"),
        CODE_REQUEST_BLOCK("code-request-blocked:"),
        PASSWORD_RESET_BLOCK("password-reset-blocked:");

        public final String prefix;

        RedisKeys(String prefix) {
            this.prefix = prefix;
        }

        public String getKeyWithTestEmailHash() {
            return prefix + TEST_EMAIL_HASH;
        }

        public String getKeyWithMfaTypeModifier(MFAMethodType mfaMethodType) {
            return prefix + mfaMethodType.getValue() + TEST_EMAIL_HASH;
        }
    }

    @BeforeAll
    static void init() {
        when(configurationService.getLockoutCountTTL()).thenReturn(CODE_EXPIRY_TIME);
        when(configurationService.getIncorrectPasswordLockoutCountTTL())
                .thenReturn(PW_CODE_EXPIRY_TIME);
        when(configurationService.getAccountCreationLockoutCountTTL())
                .thenReturn(ACCOUNT_CREATION_CODE_EXPIRY_TIME);
    }

    @Test
    void shouldCallRedisWithValidEmailCodeAndHashedEmail() {
        codeStorageService.saveOtpCode(TEST_EMAIL, CODE, CODE_EXPIRY_TIME, VERIFY_EMAIL);
        verify(redisConnectionService)
                .saveWithExpiry(
                        RedisKeys.EMAIL_OTP_CODE.getKeyWithTestEmailHash(), CODE, CODE_EXPIRY_TIME);
    }

    @Test
    void shouldRetrieveEmailCode() {
        when(redisConnectionService.getValue(RedisKeys.EMAIL_OTP_CODE.getKeyWithTestEmailHash()))
                .thenReturn(CODE);

        String codeForEmail = codeStorageService.getOtpCode(TEST_EMAIL, VERIFY_EMAIL).get();

        assertThat(codeForEmail, is(CODE));
    }

    @Test
    void shouldReturnEmptyOptionalIfEmailCodeDoesNotExist() {
        when(redisConnectionService.getValue(RedisKeys.EMAIL_OTP_CODE.getKeyWithTestEmailHash()))
                .thenReturn(null);

        assertTrue(codeStorageService.getOtpCode(TEST_EMAIL, VERIFY_EMAIL).isEmpty());
    }

    @Test
    void shouldCallRedisToDeleteEmailCodeWithHashedEmail() {
        codeStorageService.deleteOtpCode(TEST_EMAIL, VERIFY_EMAIL);

        verify(redisConnectionService)
                .deleteValue(RedisKeys.EMAIL_OTP_CODE.getKeyWithTestEmailHash());
    }

    @Test
    void shouldCallRedisWithValidPhoneNumberCodeAndHashedEmailAddress() {
        codeStorageService.saveOtpCode(
                TEST_EMAIL, CODE, CODE_EXPIRY_TIME, NotificationType.VERIFY_PHONE_NUMBER);

        verify(redisConnectionService)
                .saveWithExpiry(
                        RedisKeys.PHONE_OTP_CODE.getKeyWithTestEmailHash(), CODE, CODE_EXPIRY_TIME);
    }

    @Test
    void shouldRetrievePhoneNumberCode() {
        when(redisConnectionService.getValue(RedisKeys.PHONE_OTP_CODE.getKeyWithTestEmailHash()))
                .thenReturn(CODE);

        String codeForEmail =
                codeStorageService
                        .getOtpCode(TEST_EMAIL, NotificationType.VERIFY_PHONE_NUMBER)
                        .get();

        assertThat(codeForEmail, is(CODE));
    }

    @Test
    void shouldReturnEmptyOptionalIfPhoneNumberCodeDoesNotExist() {
        when(redisConnectionService.getValue(RedisKeys.PHONE_OTP_CODE.getKeyWithTestEmailHash()))
                .thenReturn(null);

        assertTrue(
                codeStorageService
                        .getOtpCode(TEST_EMAIL, NotificationType.VERIFY_PHONE_NUMBER)
                        .isEmpty());
    }

    @Test
    void shouldCallRedisToDeletePhoneNumberCodeWithHashedEmail() {
        codeStorageService.deleteOtpCode(TEST_EMAIL, NotificationType.VERIFY_PHONE_NUMBER);

        verify(redisConnectionService)
                .deleteValue(RedisKeys.PHONE_OTP_CODE.getKeyWithTestEmailHash());
    }

    @Test
    void shouldSaveToRedisWhenCodeIsBlockedForEmail() {
        codeStorageService.saveBlockedForEmail(
                TEST_EMAIL, RedisKeys.CODE_BLOCK.prefix, CODE_EXPIRY_TIME);

        verify(redisConnectionService)
                .saveWithExpiry(
                        RedisKeys.CODE_BLOCK.getKeyWithTestEmailHash(),
                        CODE_BLOCKED_VALUE,
                        CODE_EXPIRY_TIME);
    }

    @Test
    void shouldSaveToRedisWhenCodeRequestIsBlockedForEmail() {
        codeStorageService.saveBlockedForEmail(
                TEST_EMAIL, RedisKeys.CODE_REQUEST_BLOCK.prefix, CODE_EXPIRY_TIME);

        verify(redisConnectionService)
                .saveWithExpiry(
                        RedisKeys.CODE_REQUEST_BLOCK.getKeyWithTestEmailHash(),
                        CODE_BLOCKED_VALUE,
                        CODE_EXPIRY_TIME);
    }

    @Test
    void shouldSaveToRedisWhenPasswordResetIsBlockedForEmail() {
        codeStorageService.saveBlockedForEmail(
                TEST_EMAIL, RedisKeys.PASSWORD_RESET_BLOCK.prefix, CODE_EXPIRY_TIME);

        verify(redisConnectionService)
                .saveWithExpiry(
                        RedisKeys.PASSWORD_RESET_BLOCK.getKeyWithTestEmailHash(),
                        CODE_BLOCKED_VALUE,
                        CODE_EXPIRY_TIME);
    }

    @Test
    void shouldRetrieveEmailWhenCodeIsBlocked() {
        when(redisConnectionService.getValue(RedisKeys.CODE_BLOCK.getKeyWithTestEmailHash()))
                .thenReturn(CODE_BLOCKED_VALUE);

        assertTrue(codeStorageService.isBlockedForEmail(TEST_EMAIL, RedisKeys.CODE_BLOCK.prefix));
    }

    @Test
    void shouldRetrieveEmailWhenCodeRequestIsBlocked() {
        when(redisConnectionService.getValue(RedisKeys.CODE_BLOCK.getKeyWithTestEmailHash()))
                .thenReturn(CODE_BLOCKED_VALUE);

        assertTrue(codeStorageService.isBlockedForEmail(TEST_EMAIL, RedisKeys.CODE_BLOCK.prefix));
    }

    @Test
    void shouldRetrieveEmailWhenPasswordResetIsBlocked() {
        when(redisConnectionService.getValue(
                        RedisKeys.PASSWORD_RESET_BLOCK.getKeyWithTestEmailHash()))
                .thenReturn(CODE_BLOCKED_VALUE);

        assertTrue(
                codeStorageService.isBlockedForEmail(
                        TEST_EMAIL, RedisKeys.PASSWORD_RESET_BLOCK.prefix));
    }

    @Test
    void shouldReturnEmptyOptionalWhenCodeIsNotBlockedForSession() {
        when(redisConnectionService.getValue(RedisKeys.CODE_BLOCK.getKeyWithTestEmailHash()))
                .thenReturn(null);

        assertFalse(codeStorageService.isBlockedForEmail(TEST_EMAIL, RedisKeys.CODE_BLOCK.prefix));
    }

    @Test
    void shouldReturnEmptyOptionalWhenCodeRequestIsNotBlockedForSession() {
        when(redisConnectionService.getValue(
                        RedisKeys.CODE_REQUEST_BLOCK.getKeyWithTestEmailHash()))
                .thenReturn(null);

        assertFalse(
                codeStorageService.isBlockedForEmail(
                        TEST_EMAIL, RedisKeys.CODE_REQUEST_BLOCK.prefix));
    }

    @Test
    void shouldReturnEmptyOptionalWhenPasswordResetIsNotBlockedForSession() {
        when(redisConnectionService.getValue(
                        RedisKeys.PASSWORD_RESET_BLOCK.getKeyWithTestEmailHash()))
                .thenReturn(null);

        assertFalse(
                codeStorageService.isBlockedForEmail(
                        TEST_EMAIL, RedisKeys.PASSWORD_RESET_BLOCK.prefix));
    }

    @Test
    void shouldCallRedisWithValidMfaCodeAndHashedEmail() {
        codeStorageService.saveOtpCode(
                TEST_EMAIL, CODE, CODE_EXPIRY_TIME, NotificationType.MFA_SMS);

        verify(redisConnectionService)
                .saveWithExpiry(
                        RedisKeys.MFA_CODE.getKeyWithTestEmailHash(), CODE, CODE_EXPIRY_TIME);
    }

    @Test
    void shouldReturn0WhenThereHaveBeenNoIncorrectMfaCodeAttempts() {
        when(redisConnectionService.getValue(
                        RedisKeys.INCORRECT_MFA_COUNTER.getKeyWithTestEmailHash()))
                .thenReturn(null);
        assertThat(codeStorageService.getIncorrectMfaCodeAttemptsCount(TEST_EMAIL), equalTo(0));
    }

    @Test
    void shouldReturnNumberOfIncorrectMfaCodeAttemptsGenericKey() {
        when(redisConnectionService.getValue(
                        RedisKeys.INCORRECT_MFA_COUNTER.getKeyWithTestEmailHash()))
                .thenReturn(String.valueOf(4));
        assertThat(codeStorageService.getIncorrectMfaCodeAttemptsCount(TEST_EMAIL), equalTo(4));
    }

    @ParameterizedTest
    @CsvSource({"AUTH_APP", "SMS"})
    void shouldReturnMfaCodeBlockTimeForAuthAppAndSMS(MFAMethodType mfaMethodType) {
        var codeRequestType =
                CodeRequestType.getCodeRequestType(mfaMethodType, JourneyType.SIGN_IN);
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;
        when(redisConnectionService.getTimeToLive(codeBlockedKeyPrefix + TEST_EMAIL_HASH))
                .thenReturn(4L);
        assertThat(
                codeStorageService.getMfaCodeBlockTimeToLive(
                        TEST_EMAIL, mfaMethodType, JourneyType.SIGN_IN),
                equalTo(4L));
    }

    @Test
    void shouldCreateCountInRedisWhenThereHasBeenNoPreviousIncorrectMfaCodeAttemptGenericKey() {
        when(redisConnectionService.getValue(
                        RedisKeys.INCORRECT_MFA_COUNTER.getKeyWithTestEmailHash()))
                .thenReturn(null);
        codeStorageService.increaseIncorrectMfaCodeAttemptsCount(TEST_EMAIL);

        verify(redisConnectionService)
                .saveWithExpiry(
                        RedisKeys.INCORRECT_MFA_COUNTER.getKeyWithTestEmailHash(),
                        String.valueOf(1),
                        CODE_EXPIRY_TIME);
    }

    @Test
    void shouldIncrementCountWhenThereHasBeenPreviousIncorrectMfaCodeAttemptGenericKey() {
        when(redisConnectionService.getValue(
                        RedisKeys.INCORRECT_MFA_COUNTER.getKeyWithTestEmailHash()))
                .thenReturn(String.valueOf(3));
        codeStorageService.increaseIncorrectMfaCodeAttemptsCount(TEST_EMAIL);

        verify(redisConnectionService)
                .saveWithExpiry(
                        RedisKeys.INCORRECT_MFA_COUNTER.getKeyWithTestEmailHash(),
                        String.valueOf(4),
                        CODE_EXPIRY_TIME);
    }

    @Test
    void shouldIncrementCountForIncorrectMfaCodeAttemptsCountAccountCreation() {
        when(redisConnectionService.getValue(
                        RedisKeys.INCORRECT_MFA_COUNTER.getKeyWithTestEmailHash()))
                .thenReturn(String.valueOf(0));

        codeStorageService.increaseIncorrectMfaCodeAttemptsCountAccountCreation(TEST_EMAIL);

        verify(redisConnectionService)
                .saveWithExpiry(
                        RedisKeys.INCORRECT_MFA_COUNTER.getKeyWithTestEmailHash(),
                        String.valueOf(1),
                        ACCOUNT_CREATION_CODE_EXPIRY_TIME);
    }

    @Test
    void shouldCallRedisToDeleteIncorrectMfaCodeAttemptCountGenericKey() {
        codeStorageService.deleteIncorrectMfaCodeAttemptsCount(TEST_EMAIL);

        verify(redisConnectionService)
                .deleteValue(RedisKeys.INCORRECT_MFA_COUNTER.getKeyWithTestEmailHash());
    }

    @Test
    void shouldReturn0WhenThereHasBeenNoInvalidPasswordAttempts() {
        when(redisConnectionService.getValue(
                        RedisKeys.INCORRECT_PASSWORD_COUNTER.getKeyWithTestEmailHash()))
                .thenReturn(null);
        assertThat(codeStorageService.getIncorrectPasswordCount(TEST_EMAIL), equalTo(0));
    }

    @Test
    void shouldReturnNumberOfInvalidPasswordAttempts() {
        when(redisConnectionService.getValue(
                        RedisKeys.INCORRECT_PASSWORD_COUNTER.getKeyWithTestEmailHash()))
                .thenReturn(String.valueOf(4));
        assertThat(codeStorageService.getIncorrectPasswordCount(TEST_EMAIL), equalTo(4));
    }

    @Test
    void shouldCreateCountInRedisWhenThereHasBeenNoPreviousIncorrectPasswordAttempt() {
        when(redisConnectionService.getValue(
                        RedisKeys.INCORRECT_PASSWORD_COUNTER.getKeyWithTestEmailHash()))
                .thenReturn(null);
        codeStorageService.increaseIncorrectPasswordCount(TEST_EMAIL);

        verify(redisConnectionService)
                .saveWithExpiry(
                        RedisKeys.INCORRECT_PASSWORD_COUNTER.getKeyWithTestEmailHash(),
                        String.valueOf(1),
                        CODE_EXPIRY_TIME);
    }

    @Test
    void shouldIncrementCountWhenThereHasBeenPreviousIncorrectPasswordAttempts() {
        when(redisConnectionService.getValue(
                        RedisKeys.INCORRECT_PASSWORD_COUNTER.getKeyWithTestEmailHash()))
                .thenReturn(String.valueOf(3));
        codeStorageService.increaseIncorrectPasswordCount(TEST_EMAIL);

        verify(redisConnectionService)
                .saveWithExpiry(
                        RedisKeys.INCORRECT_PASSWORD_COUNTER.getKeyWithTestEmailHash(),
                        String.valueOf(4),
                        CODE_EXPIRY_TIME);
    }

    @Test
    void shouldCallRedisToDeleteIncorrectPasswordCount() {
        codeStorageService.deleteIncorrectPasswordCount(TEST_EMAIL);

        verify(redisConnectionService)
                .deleteValue(RedisKeys.INCORRECT_PASSWORD_COUNTER.getKeyWithTestEmailHash());
    }
}
