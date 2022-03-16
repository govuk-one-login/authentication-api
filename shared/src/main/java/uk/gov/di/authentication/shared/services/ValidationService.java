package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.Session;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ValidationService {

    private static final Pattern EMAIL_NOTIFY_REGEX =
            Pattern.compile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~\\-]+@([^.@][^@\\s]+)$");
    private static final Pattern HOSTNAME_REGEX =
            Pattern.compile("^(xn|[a-z0-9]+)(-?-[a-z0-9]+)*$", Pattern.CASE_INSENSITIVE);
    private static final Pattern TLD_PART_REGEX =
            Pattern.compile("^([a-z]{2,63}|xn--([a-z0-9]+-)*[a-z0-9]+)$", Pattern.CASE_INSENSITIVE);

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

    public Optional<ErrorResponse> validateVerificationCode(
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
            }
        }

        switch (type) {
            case MFA_SMS:
                return Optional.of(ErrorResponse.ERROR_1035);
            case VERIFY_EMAIL:
                return Optional.of(ErrorResponse.ERROR_1036);
            case VERIFY_PHONE_NUMBER:
                return Optional.of(ErrorResponse.ERROR_1037);
        }
        return Optional.of(ErrorResponse.ERROR_1002);
    }
}
