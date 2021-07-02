package uk.gov.di.services;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import uk.gov.di.entity.ErrorResponse;

import java.util.Optional;
import java.util.regex.Pattern;

public class ValidationService {

    private static final Pattern EMAIL_REGEX = Pattern.compile("[^@]+@[^@]+\\.[^@]*");
    private static final Pattern PASSWORD_REGEX = Pattern.compile(".*\\d.*");

    public Optional<ErrorResponse> validateEmailAddress(String email) {
        if (email.isBlank()) {
            return Optional.of(ErrorResponse.ERROR_1003);
        }
        if (!email.isBlank() && !EMAIL_REGEX.matcher(email).matches()) {
            return Optional.of(ErrorResponse.ERROR_1004);
        }
        return Optional.empty();
    }

    public Optional<ErrorResponse> validatePassword(String password) {
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

    public Optional<ErrorResponse> validatePhoneNumber(String phoneNumberInput) {
        if ((!phoneNumberInput.matches("[0-9]+")) || (phoneNumberInput.length() < 10)) {
            return Optional.of(ErrorResponse.ERROR_1012);
        }
        PhoneNumberUtil phoneUtil = PhoneNumberUtil.getInstance();
        try {
            var phoneNumber = phoneUtil.parse(phoneNumberInput, "GB");
            if (phoneUtil.isValidNumber(phoneNumber)) {
                return Optional.empty();
            }
            return Optional.of(ErrorResponse.ERROR_1012);
        } catch (NumberParseException e) {
            return Optional.of(ErrorResponse.ERROR_1012);
        }
    }
}
