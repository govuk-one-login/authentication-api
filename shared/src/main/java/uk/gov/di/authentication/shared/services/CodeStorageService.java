package uk.gov.di.authentication.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.HashHelper;

import java.util.Optional;

import static java.lang.String.format;

public class CodeStorageService {

    public static final String CODE_REQUEST_BLOCKED_KEY_PREFIX = "code-request-blocked:";
    public static final String CODE_BLOCKED_KEY_PREFIX = "code-blocked:";
    public static final String PASSWORD_BLOCKED_KEY_PREFIX = "password-blocked:";

    private static final Logger LOG = LogManager.getLogger(CodeStorageService.class);

    private final RedisConnectionService redisConnectionService;
    private final ConfigurationService configurationService;
    private static final String EMAIL_KEY_PREFIX = "email-code:";
    private static final String PHONE_NUMBER_KEY_PREFIX = "phone-number-code:";
    private static final String MFA_KEY_PREFIX = "mfa-code:";

    private static final String MULTIPLE_INCORRECT_MFA_CODES_KEY_PREFIX =
            "multiple-incorrect-mfa-codes:";
    private static final String CODE_BLOCKED_VALUE = "blocked";
    private static final String RESET_PASSWORD_KEY_PREFIX = "reset-password-code:";
    private static final String MULTIPLE_INCORRECT_PASSWORDS_PREFIX =
            "multiple-incorrect-passwords:";
    private static final String MULTIPLE_INCORRECT_REAUTH_EMAIL_PREFIX =
            "multiple-incorrect-reauth-email:";
    private static final String MULTIPLE_INCORRECT_PASSWORDS_REAUTH_PREFIX =
            "multiple-incorrect-passwords-reauth:";

    private static final String VERIFY_CHANGE_HOW_GET_SECURITY_CODES_KEY_PREFIX =
            "change-how-get-security-codes";

    public CodeStorageService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.redisConnectionService = new RedisConnectionService(configurationService);
    }

    public CodeStorageService(
            ConfigurationService configurationService,
            RedisConnectionService redisConnectionService) {
        this.configurationService = configurationService;
        this.redisConnectionService = redisConnectionService;
    }

    public void increaseIncorrectMfaCodeAttemptsCount(String email) {
        increaseCount(
                email,
                MULTIPLE_INCORRECT_MFA_CODES_KEY_PREFIX,
                configurationService.getLockoutCountTTL());
    }

    public void increaseIncorrectMfaCodeAttemptsCountAccountCreation(String email) {
        increaseCount(
                email,
                MULTIPLE_INCORRECT_MFA_CODES_KEY_PREFIX,
                configurationService.getAccountCreationLockoutCountTTL());
    }

    public int getIncorrectMfaCodeAttemptsCount(String email) {
        return getCount(email, MULTIPLE_INCORRECT_MFA_CODES_KEY_PREFIX)
                // TODO remove temporary ZDD measure to fetch existing counts using deprecated
                //  prefixes
                + getCount(
                        email,
                        MULTIPLE_INCORRECT_MFA_CODES_KEY_PREFIX + MFAMethodType.SMS.getValue())
                + getCount(
                        email,
                        MULTIPLE_INCORRECT_MFA_CODES_KEY_PREFIX
                                + MFAMethodType.AUTH_APP.getValue());
    }

    public void deleteIncorrectMfaCodeAttemptsCount(String email) {
        deleteCount(email, MULTIPLE_INCORRECT_MFA_CODES_KEY_PREFIX);
        // TODO remove temporary ZDD measure to delete existing counts using deprecated prefixes
        deleteCount(email, MULTIPLE_INCORRECT_MFA_CODES_KEY_PREFIX + MFAMethodType.SMS.getValue());
        deleteCount(
                email, MULTIPLE_INCORRECT_MFA_CODES_KEY_PREFIX + MFAMethodType.AUTH_APP.getValue());
    }

    public void increaseIncorrectPasswordCount(String email) {
        increaseCount(
                email,
                MULTIPLE_INCORRECT_PASSWORDS_PREFIX,
                configurationService.getIncorrectPasswordLockoutCountTTL());
    }

    public int getIncorrectPasswordCount(String email) {
        return getCount(email, MULTIPLE_INCORRECT_PASSWORDS_PREFIX);
    }

    public void deleteIncorrectPasswordCount(String email) {
        deleteCount(email, MULTIPLE_INCORRECT_PASSWORDS_PREFIX);
    }

    public void increaseIncorrectEmailCount(String email) {
        increaseCount(
                email,
                MULTIPLE_INCORRECT_REAUTH_EMAIL_PREFIX,
                configurationService.getLockoutCountTTL());
    }

    public int getIncorrectEmailCount(String email) {
        return getCount(email, MULTIPLE_INCORRECT_REAUTH_EMAIL_PREFIX);
    }

    public void deleteIncorrectEmailCount(String email) {
        deleteCount(email, MULTIPLE_INCORRECT_REAUTH_EMAIL_PREFIX);
    }

    public void increaseIncorrectPasswordCountReauthJourney(String email) {
        increaseCount(
                email,
                MULTIPLE_INCORRECT_PASSWORDS_REAUTH_PREFIX,
                configurationService.getLockoutCountTTL());
    }

    public int getIncorrectPasswordCountReauthJourney(String email) {
        return getCount(email, MULTIPLE_INCORRECT_PASSWORDS_REAUTH_PREFIX);
    }

    public void deleteIncorrectPasswordCountReauthJourney(String email) {
        deleteCount(email, MULTIPLE_INCORRECT_PASSWORDS_REAUTH_PREFIX);
    }

    public long getMfaCodeBlockTimeToLive(
            String email, MFAMethodType mfaMethodType, JourneyType journeyType) {
        var codeRequestType = CodeRequestType.getCodeRequestType(mfaMethodType, journeyType);
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;
        long finalTtl = getTTL(email, codeBlockedKeyPrefix);

        // TODO remove temporary ZDD measure to reference existing deprecated keys when expired
        var deprecatedCodeRequestType =
                CodeRequestType.getDeprecatedCodeRequestTypeString(mfaMethodType, journeyType);
        if (deprecatedCodeRequestType != null) {
            long possibleOverrideTtl =
                    getTTL(email, CODE_BLOCKED_KEY_PREFIX + deprecatedCodeRequestType);
            finalTtl = Math.max(finalTtl, possibleOverrideTtl);
        }

        return finalTtl;
    }

    public void saveBlockedForEmail(String email, String prefix, long codeBlockedTime) {
        String encodedHash = HashHelper.hashSha256String(email);
        String key = prefix + encodedHash;
        try {
            redisConnectionService.saveWithExpiry(key, CODE_BLOCKED_VALUE, codeBlockedTime);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void deleteBlockForEmail(String email, String prefix) {
        String encodedHash = HashHelper.hashSha256String(email);
        String keys = prefix + encodedHash;
        try {
            redisConnectionService.deleteValue(keys);
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to remove the block for this value");
        }
    }

    public boolean isBlockedForEmail(String emailAddress, String prefix) {
        String value =
                redisConnectionService.getValue(prefix + HashHelper.hashSha256String(emailAddress));
        LOG.info("block value: {}", value);
        return value != null;
    }

    public void saveOtpCode(
            String unhashedIdentifier,
            String code,
            long codeExpiryTime,
            NotificationType notificationType) {
        String hashedIdentifier = HashHelper.hashSha256String(unhashedIdentifier);
        String prefix = getPrefixForNotificationType(notificationType);
        String key = prefix + hashedIdentifier;
        try {
            redisConnectionService.saveWithExpiry(key, code, codeExpiryTime);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Optional<String> getOtpCode(
            String unhashedIdentifier, NotificationType notificationType) {
        String prefix = getPrefixForNotificationType(notificationType);
        return Optional.ofNullable(
                redisConnectionService.getValue(
                        prefix + HashHelper.hashSha256String(unhashedIdentifier)));
    }

    public void deleteOtpCode(String unhashedIdentifier, NotificationType notificationType) {
        String prefix = getPrefixForNotificationType(notificationType);
        long numberOfKeysRemoved =
                redisConnectionService.deleteValue(
                        prefix + HashHelper.hashSha256String(unhashedIdentifier));

        if (numberOfKeysRemoved == 0) {
            LOG.info(format("No %s key was deleted", prefix));
        }
    }

    private String getPrefixForNotificationType(NotificationType notificationType) {
        switch (notificationType) {
            case VERIFY_EMAIL:
                return EMAIL_KEY_PREFIX;
            case VERIFY_PHONE_NUMBER:
                return PHONE_NUMBER_KEY_PREFIX;
            case MFA_SMS:
                return MFA_KEY_PREFIX;
            case RESET_PASSWORD_WITH_CODE:
                return RESET_PASSWORD_KEY_PREFIX;
            case VERIFY_CHANGE_HOW_GET_SECURITY_CODES:
                return VERIFY_CHANGE_HOW_GET_SECURITY_CODES_KEY_PREFIX;
        }
        throw new RuntimeException(
                String.format("No redis prefix key configured for %s", notificationType));
    }

    private void increaseCount(String email, String prefix, long ttl) {
        String encodedHash = HashHelper.hashSha256String(email);
        String key = prefix + encodedHash;
        Optional<String> count = Optional.ofNullable(redisConnectionService.getValue(key));
        int newCount = count.map(t -> Integer.parseInt(t) + 1).orElse(1);
        try {
            redisConnectionService.saveWithExpiry(key, String.valueOf(newCount), ttl);
            LOG.info("count increased from: {} to: {}", count, newCount);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private int getCount(String email, String prefix) {
        Optional<String> count =
                Optional.ofNullable(
                        redisConnectionService.getValue(
                                prefix + HashHelper.hashSha256String(email)));
        return count.map(Integer::parseInt).orElse(0);
    }

    private void deleteCount(String email, String prefix) {
        String encodedHash = HashHelper.hashSha256String(email);
        String key = prefix + encodedHash;

        try {
            redisConnectionService.deleteValue(key);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private long getTTL(String email, String prefix) {
        return redisConnectionService.getTimeToLive(prefix + HashHelper.hashSha256String(email));
    }
}
