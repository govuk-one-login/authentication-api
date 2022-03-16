package uk.gov.di.authentication.shared.helpers;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import uk.gov.di.authentication.shared.entity.ErrorResponse;

import java.util.Optional;
import java.util.regex.Pattern;

import static com.google.i18n.phonenumbers.PhoneNumberUtil.PhoneNumberType.MOBILE;

public class ValidationHelper {

    private static final Pattern PASSWORD_REGEX = Pattern.compile(".*\\d.*");

    private ValidationHelper() {}

    public static Optional<ErrorResponse> validatePhoneNumber(String phoneNumberInput) {
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
}
