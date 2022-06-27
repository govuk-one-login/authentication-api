package uk.gov.di.authentication.shared.helpers;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.Session;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.google.i18n.phonenumbers.PhoneNumberUtil.PhoneNumberType.MOBILE;

public class ValidationHelper {

    private static final Pattern PASSWORD_REGEX = Pattern.compile(".*\\d.*");
    private static final Pattern EMAIL_NOTIFY_REGEX =
            Pattern.compile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~\\-]+@([^.@][^@\\s]+)$");
    private static final Pattern HOSTNAME_REGEX =
            Pattern.compile("^(xn|[a-z0-9]+)(-?-[a-z0-9]+)*$", Pattern.CASE_INSENSITIVE);
    private static final Pattern TLD_PART_REGEX =
            Pattern.compile("^([a-z]{2,63}|xn--([a-z0-9]+-)*[a-z0-9]+)$", Pattern.CASE_INSENSITIVE);
    private static final List<String> ALLOWED_TEST_NUMBERS = List.of("07700900222");

    private ValidationHelper() {}

    public static Optional<ErrorResponse> validatePhoneNumber(
            String currentPhoneNumber, String newPhoneNumber) {
        if (Objects.nonNull(currentPhoneNumber)
                && currentPhoneNumber.equals(PhoneNumberHelper.formatPhoneNumber(newPhoneNumber))) {
            return Optional.of(ErrorResponse.ERROR_1044);
        }
        return validatePhoneNumber(newPhoneNumber);
    }

    public static Optional<ErrorResponse> validatePhoneNumber(String phoneNumberInput) {
        if (ALLOWED_TEST_NUMBERS.contains(phoneNumberInput)) return Optional.empty();
        if ((!phoneNumberInput.startsWith("+"))
                && ((!phoneNumberInput.matches("[0-9]+")) || (phoneNumberInput.length() < 10))) {
            return Optional.of(ErrorResponse.ERROR_1012);
        }
        var phoneUtil = PhoneNumberUtil.getInstance();
        try {
            var phoneNumber = phoneUtil.parse(phoneNumberInput, "GB");
            if (!phoneUtil.getNumberType(phoneNumber).equals(MOBILE)) {
                return Optional.of(ErrorResponse.ERROR_1012);
            }
            if (phoneUtil.isValidNumber(phoneNumber)) {
                return Optional.empty();
            }
            return Optional.of(ErrorResponse.ERROR_1012);
        } catch (NumberParseException e) {
            return Optional.of(ErrorResponse.ERROR_1012);
        }
    }

    public static Optional<ErrorResponse> validatePassword(String password) {
        if (password == null || password.isBlank()) {
            return Optional.of(ErrorResponse.ERROR_1005);
        }
        if (password.length() < 8) {
            return Optional.of(ErrorResponse.ERROR_1006);
        }
        if (!PASSWORD_REGEX.matcher(password).matches()) {
            return Optional.of(ErrorResponse.ERROR_1007);
        }
        return Optional.empty();
    }

    public static boolean hasAtLeastOneDigit(String string) {
        char[] charArray = string.toCharArray();
        for (char c : charArray) {
            if (Character.isDigit(c)) {
                return true;
            }
        }
        return false;
    }

    public static Optional<ErrorResponse> validateEmailAddressUpdate(
            String existingEmail, String replacementEmail) {
        if (existingEmail.equals(replacementEmail)) {
            return Optional.of(ErrorResponse.ERROR_1019);
        }
        Optional<ErrorResponse> existingEmailError = validateEmailAddress(existingEmail);
        if (existingEmailError.isPresent()) {
            return existingEmailError;
        }
        return validateEmailAddress(replacementEmail);
    }

    public static Optional<ErrorResponse> validateEmailAddress(String email) {
        if (email == null || email.isBlank()) {
            return Optional.of(ErrorResponse.ERROR_1003);
        }
        Matcher matcher = EMAIL_NOTIFY_REGEX.matcher(email);
        if (!matcher.matches()) {
            return Optional.of(ErrorResponse.ERROR_1004);
        }
        if (email.contains("..")) {
            return Optional.of(ErrorResponse.ERROR_1004);
        }
        var hostname = matcher.group(1);
        String[] parts = hostname.split("\\.");
        if (parts.length < 2) {
            return Optional.of(ErrorResponse.ERROR_1004);
        }
        for (String part : parts) {
            if (!HOSTNAME_REGEX.matcher(part).matches()) {
                return Optional.of(ErrorResponse.ERROR_1004);
            }
        }
        if (!TLD_PART_REGEX.matcher(parts[parts.length - 1]).matches()) {
            return Optional.of(ErrorResponse.ERROR_1004);
        }
        return Optional.empty();
    }

    public static Optional<ErrorResponse> validateVerificationCode(
            NotificationType type,
            Optional<String> code,
            String input,
            Session session,
            int maxRetries) {

        if (code.filter(input::equals).isPresent()) {
            session.resetCodeRequestCount();

            switch (type) {
                case MFA_SMS:
                case VERIFY_EMAIL:
                case VERIFY_PHONE_NUMBER:
                case RESET_PASSWORD_WITH_CODE:
                    return Optional.empty();
            }
            return Optional.of(ErrorResponse.ERROR_1002);
        }

        session.incrementRetryCount();

        if (session.getRetryCount() > maxRetries) {
            switch (type) {
                case MFA_SMS:
                    return Optional.of(ErrorResponse.ERROR_1027);
                case VERIFY_EMAIL:
                    return Optional.of(ErrorResponse.ERROR_1033);
                case VERIFY_PHONE_NUMBER:
                    return Optional.of(ErrorResponse.ERROR_1034);
                case RESET_PASSWORD_WITH_CODE:
                    return Optional.of(ErrorResponse.ERROR_1039);
            }
        }

        switch (type) {
            case MFA_SMS:
                return Optional.of(ErrorResponse.ERROR_1035);
            case VERIFY_EMAIL:
                return Optional.of(ErrorResponse.ERROR_1036);
            case VERIFY_PHONE_NUMBER:
                return Optional.of(ErrorResponse.ERROR_1037);
            case RESET_PASSWORD_WITH_CODE:
                return Optional.of(ErrorResponse.ERROR_1021);
        }
        return Optional.of(ErrorResponse.ERROR_1002);
    }
}
