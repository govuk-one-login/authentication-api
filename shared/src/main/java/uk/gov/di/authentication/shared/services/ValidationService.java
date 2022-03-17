package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.Session;

import java.util.Optional;

public class ValidationService {

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
