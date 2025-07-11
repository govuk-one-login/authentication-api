package uk.gov.di.authentication.shared.helpers;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.PhoneNumberUtil.PhoneNumberType;
import com.google.i18n.phonenumbers.Phonenumber;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jetbrains.annotations.NotNull;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.google.i18n.phonenumbers.PhoneNumberUtil.PhoneNumberType.FIXED_LINE_OR_MOBILE;
import static com.google.i18n.phonenumbers.PhoneNumberUtil.PhoneNumberType.MOBILE;
import static uk.gov.di.authentication.entity.Environment.PRODUCTION;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;

public class ValidationHelper {
    private static final Logger LOG = LogManager.getLogger(ValidationHelper.class);
    private static final Pattern EMAIL_NOTIFY_REGEX =
            Pattern.compile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~\\-]+@([^.@][^@\\s]+)$");
    private static final Pattern HOSTNAME_REGEX =
            Pattern.compile("^(xn|[a-z0-9]+)(-?-[a-z0-9]+)*$", Pattern.CASE_INSENSITIVE);
    private static final Pattern TLD_PART_REGEX =
            Pattern.compile(
                    "^(?:[a-z]{2,63}|xn--[a-z0-9]+(?:-[a-z0-9]+){1,4})(?:$|[^-])",
                    Pattern.CASE_INSENSITIVE);
    private static final List<String> ALLOWED_TEST_NUMBERS =
            List.of(
                    "07700900222",
                    "07700900000",
                    "07700900111",
                    "+447700900000",
                    "+447700900111",
                    "+447700900222");

    private ValidationHelper() {}

    public static Optional<ErrorResponse> validatePhoneNumber(
            String phoneNumberInput, String environment, boolean isSmokeTest) {
        if (isValidTestNumberForEnvironment(phoneNumberInput, environment, isSmokeTest)) {
            return Optional.empty();
        }

        if ((phoneNumberInput.length() < 5) || (phoneNumberInput.length() > 25)) {
            LOG.warn("Invalid phone number: length check");
            return Optional.of(ErrorResponse.INVALID_PHONE_NUMBER);
        }

        var phoneUtil = PhoneNumberUtil.getInstance();

        Phonenumber.PhoneNumber phoneNumber;

        try {
            phoneNumber = phoneUtil.parse(phoneNumberInput, "GB");
        } catch (NumberParseException e) {
            LOG.warn("Invalid phone number: parsing failure");
            return Optional.of(ErrorResponse.INVALID_PHONE_NUMBER);
        }

        var phoneNumberType = phoneUtil.getNumberType(phoneNumber);
        if (!isAcceptedPhoneNumberType(phoneNumberType)) {
            LOG.warn("Invalid phone number: not a mobile number.  NumberType {}", phoneNumberType);
            return Optional.of(ErrorResponse.INVALID_PHONE_NUMBER);
        }
        LOG.info("Accepted phone NumberType {}", phoneNumberType);
        return Optional.empty();
    }

    static boolean isAcceptedPhoneNumberType(PhoneNumberType phoneNumberType) {
        return MOBILE.equals(phoneNumberType) || FIXED_LINE_OR_MOBILE.equals(phoneNumberType);
    }

    public static Optional<ErrorResponse> validateEmailAddressUpdate(
            String existingEmail, String replacementEmail) {
        if (existingEmail.equals(replacementEmail)) {
            return Optional.of(ErrorResponse.EMAIL_ADDRESSES_MATCH);
        }
        Optional<ErrorResponse> existingEmailError = validateEmailAddress(existingEmail);
        if (existingEmailError.isPresent()) {
            return existingEmailError;
        }
        return validateEmailAddress(replacementEmail);
    }

    public static Optional<ErrorResponse> validateEmailAddress(String email) {
        if (email == null || email.isBlank()) {
            return Optional.of(ErrorResponse.EMAIL_ADDRESS_EMPTY);
        }
        Matcher matcher = EMAIL_NOTIFY_REGEX.matcher(email);
        if (!matcher.matches()) {
            return Optional.of(ErrorResponse.INVALID_EMAIL_FORMAT);
        }
        if (email.contains("..")) {
            return Optional.of(ErrorResponse.INVALID_EMAIL_FORMAT);
        }
        var hostname = matcher.group(1);
        String[] parts = hostname.split("\\.");
        if (parts.length < 2) {
            return Optional.of(ErrorResponse.INVALID_EMAIL_FORMAT);
        }
        for (String part : parts) {
            if (!HOSTNAME_REGEX.matcher(part).matches()) {
                return Optional.of(ErrorResponse.INVALID_EMAIL_FORMAT);
            }
        }
        if (!TLD_PART_REGEX.matcher(parts[parts.length - 1]).matches()) {
            return Optional.of(ErrorResponse.INVALID_EMAIL_FORMAT);
        }
        return Optional.empty();
    }

    public static Optional<ErrorResponse> validateVerificationCode(
            NotificationType notificationType,
            JourneyType journeyType,
            Optional<String> code,
            String input,
            CodeStorageService codeStorageService,
            String emailAddress,
            ConfigurationService configurationService) {

        if (code.filter(input::equals).isPresent()) {
            if (journeyType != JourneyType.REAUTHENTICATION) {
                codeStorageService.deleteIncorrectMfaCodeAttemptsCount(emailAddress);
            }

            switch (notificationType) {
                case MFA_SMS:
                case VERIFY_EMAIL:
                case VERIFY_CHANGE_HOW_GET_SECURITY_CODES:
                case VERIFY_PHONE_NUMBER:
                case RESET_PASSWORD_WITH_CODE:
                    return Optional.empty();
            }
            return Optional.of(ErrorResponse.INVALID_NOTIFICATION_TYPE);
        }

        return getErrorResponse(
                notificationType,
                journeyType,
                codeStorageService,
                emailAddress,
                configurationService);
    }

    private static @NotNull Optional<ErrorResponse> getErrorResponse(
            NotificationType notificationType,
            JourneyType journeyType,
            CodeStorageService codeStorageService,
            String emailAddress,
            ConfigurationService configurationService) {
        if (journeyType != JourneyType.REAUTHENTICATION) {
            if (configurationService.supportAccountCreationTTL()
                    && notificationType == VERIFY_EMAIL) {
                codeStorageService.increaseIncorrectMfaCodeAttemptsCountAccountCreation(
                        emailAddress);
            } else {
                codeStorageService.increaseIncorrectMfaCodeAttemptsCount(emailAddress);
            }

            if (codeStorageService.getIncorrectMfaCodeAttemptsCount(emailAddress)
                    >= configurationService.getCodeMaxRetries()) {
                switch (notificationType) {
                    case MFA_SMS:
                        return Optional.of(ErrorResponse.TOO_MANY_INVALID_MFA_OTPS_ENTERED);
                    case VERIFY_EMAIL:
                        return Optional.of(ErrorResponse.TOO_MANY_EMAIL_CODES_ENTERED);
                    case VERIFY_CHANGE_HOW_GET_SECURITY_CODES:
                        return Optional.of(
                                ErrorResponse.TOO_MANY_EMAIL_CODES_FOR_MFA_RESET_ENTERED);
                    case VERIFY_PHONE_NUMBER:
                        return Optional.of(ErrorResponse.TOO_MANY_PHONE_CODES_ENTERED);
                    case RESET_PASSWORD_WITH_CODE:
                        return Optional.of(ErrorResponse.TOO_MANY_INVALID_PW_RESET_CODES_ENTERED);
                }
            }
        }

        switch (notificationType) {
            case MFA_SMS:
                return Optional.of(ErrorResponse.INVALID_MFA_CODE_ENTERED);
            case VERIFY_EMAIL:
            case VERIFY_CHANGE_HOW_GET_SECURITY_CODES:
                return Optional.of(ErrorResponse.INVALID_EMAIL_CODE_ENTERED);
            case VERIFY_PHONE_NUMBER:
                return Optional.of(ErrorResponse.INVALID_PHONE_CODE_ENTERED);
            case RESET_PASSWORD_WITH_CODE:
                return Optional.of(ErrorResponse.INVALID_PW_RESET_CODE);
        }
        return Optional.of(ErrorResponse.INVALID_NOTIFICATION_TYPE);
    }

    public static boolean isValidTestNumberForEnvironment(
            String phoneNumberInput, String environment, boolean isSmokeTest) {
        if (ALLOWED_TEST_NUMBERS.contains(phoneNumberInput)
                && !Objects.equals(environment, PRODUCTION.getValue())) {
            LOG.info("Allowed test number: non-prod");
            return true;
        }
        if (ALLOWED_TEST_NUMBERS.contains(phoneNumberInput)
                && Objects.equals(environment, PRODUCTION.getValue())
                && isSmokeTest) {
            LOG.info("Allowed test number: prod smoke test");
            return true;
        }
        return false;
    }
}
