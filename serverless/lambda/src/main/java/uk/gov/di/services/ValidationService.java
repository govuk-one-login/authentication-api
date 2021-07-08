package uk.gov.di.services;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.Session;
import uk.gov.di.entity.SessionState;

import java.util.Optional;
import java.util.regex.Pattern;

import static uk.gov.di.entity.SessionState.EMAIL_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.entity.SessionState.EMAIL_CODE_NOT_VALID;
import static uk.gov.di.entity.SessionState.EMAIL_CODE_VERIFIED;
import static uk.gov.di.entity.SessionState.PHONE_NUMBER_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.entity.SessionState.PHONE_NUMBER_CODE_NOT_VALID;
import static uk.gov.di.entity.SessionState.PHONE_NUMBER_CODE_VERIFIED;

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

    public SessionState validatePhoneVerificationCode(
            Optional<String> phoneNumberCode, String input, Session session, int maxRetries) {
        if (phoneNumberCode.isEmpty() || !phoneNumberCode.get().equals(input)) {
            session.incrementRetryCount();
            if (session.getRetryCount() > maxRetries) {
                return PHONE_NUMBER_CODE_MAX_RETRIES_REACHED;
            } else {
                return PHONE_NUMBER_CODE_NOT_VALID;
            }
        }
        return PHONE_NUMBER_CODE_VERIFIED;
    }

    public SessionState validateEmailVerificationCode(
            Optional<String> emailCode, String input, Session session, int maxRetries) {
        if (emailCode.isEmpty() || !emailCode.get().equals(input)) {
            session.incrementRetryCount();
            if (session.getRetryCount() > maxRetries) {
                return EMAIL_CODE_MAX_RETRIES_REACHED;
            } else {
                return EMAIL_CODE_NOT_VALID;
            }
        }
        return EMAIL_CODE_VERIFIED;
    }
}
