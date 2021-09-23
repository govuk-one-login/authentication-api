package uk.gov.di.authentication.shared.services;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionAction;

import java.util.Optional;
import java.util.regex.Pattern;

import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE_TOO_MANY_TIMES;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_MFA_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_MFA_CODE_TOO_MANY_TIMES;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE_TOO_MANY_TIMES;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_VALID_EMAIL_VERIFICATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_VALID_MFA_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_VALID_PHONE_VERIFICATION_CODE;

public class ValidationService {

    private static final Pattern EMAIL_REGEX = Pattern.compile("[^@]+@[^@]+\\.[^@]*");
    private static final Pattern PASSWORD_REGEX = Pattern.compile(".*\\d.*");

    public Optional<ErrorResponse> validateEmailAddressUpdate(
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

    public SessionAction validatePhoneVerificationCode(
            Optional<String> phoneNumberCode, String input, Session session, int maxRetries) {
        if (phoneNumberCode.isEmpty() || !phoneNumberCode.get().equals(input)) {
            session.incrementRetryCount();
            if (session.getRetryCount() > maxRetries) {
                return USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE_TOO_MANY_TIMES;
            } else {
                return USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE;
            }
        }
        session.resetCodeRequestCount();
        return USER_ENTERED_VALID_PHONE_VERIFICATION_CODE;
    }

    public SessionAction validateMfaVerificationCode(
            Optional<String> mfaCode, String input, Session session, int maxRetries) {
        if (mfaCode.isEmpty() || !mfaCode.get().equals(input)) {
            session.incrementRetryCount();
            if (session.getRetryCount() > maxRetries) {
                return USER_ENTERED_INVALID_MFA_CODE_TOO_MANY_TIMES;
            } else {
                return USER_ENTERED_INVALID_MFA_CODE;
            }
        }
        session.resetCodeRequestCount();
        return USER_ENTERED_VALID_MFA_CODE;
    }

    public SessionAction validateEmailVerificationCode(
            Optional<String> emailCode, String input, Session session, int maxRetries) {
        if (emailCode.isEmpty() || !emailCode.get().equals(input)) {
            session.incrementRetryCount();
            if (session.getRetryCount() > maxRetries) {
                return USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE_TOO_MANY_TIMES;
            } else {
                return USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE;
            }
        }
        session.resetCodeRequestCount();
        return USER_ENTERED_VALID_EMAIL_VERIFICATION_CODE;
    }

    public SessionAction validateVerificationCode(
            NotificationType type,
            Optional<String> code,
            String input,
            Session session,
            int maxRetries) {

        if (code.filter(input::equals).isPresent()) {
            session.resetCodeRequestCount();

            switch (type) {
                case MFA_SMS:
                    return USER_ENTERED_VALID_MFA_CODE;
                case VERIFY_EMAIL:
                    return USER_ENTERED_VALID_EMAIL_VERIFICATION_CODE;
                case VERIFY_PHONE_NUMBER:
                    return USER_ENTERED_VALID_PHONE_VERIFICATION_CODE;
            }
        }

        session.incrementRetryCount();

        if (session.getRetryCount() > maxRetries) {
            switch (type) {
                case MFA_SMS:
                    return USER_ENTERED_INVALID_MFA_CODE_TOO_MANY_TIMES;
                case VERIFY_EMAIL:
                    return USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE_TOO_MANY_TIMES;
                case VERIFY_PHONE_NUMBER:
                    return USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE_TOO_MANY_TIMES;
            }
        }

        switch (type) {
            case MFA_SMS:
                return USER_ENTERED_INVALID_MFA_CODE;
            case VERIFY_EMAIL:
                return USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE;
            case VERIFY_PHONE_NUMBER:
                return USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE;
        }

        return null;
    }
}
