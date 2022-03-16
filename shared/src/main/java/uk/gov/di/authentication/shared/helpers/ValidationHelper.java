package uk.gov.di.authentication.shared.helpers;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import uk.gov.di.authentication.shared.entity.ErrorResponse;

import java.util.Optional;

import static com.google.i18n.phonenumbers.PhoneNumberUtil.PhoneNumberType.MOBILE;

public class ValidationHelper {

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
}
