package uk.gov.di.authentication.shared.validation;

import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;

import java.util.Optional;

public class PasswordValidator {

    private final CommonPasswordsService commonPasswordsService;

    public PasswordValidator(CommonPasswordsService commonPasswordsService) {
        this.commonPasswordsService = commonPasswordsService;
    }

    public Optional<ErrorResponse> validate(String password) {

        if (password == null || password.isBlank()) {
            return Optional.of(ErrorResponse.PW_EMPTY);
        }
        if (password.length() < 8 || password.length() > 256) {
            return Optional.of(ErrorResponse.INVALID_PW_LENGTH);
        }
        if (!hasAtLeastOneDigitAndOneNonDigit(password)) {
            return Optional.of(ErrorResponse.INVALID_PW_CHARS);
        }

        if (commonPasswordsService.isCommonPassword(password)) {
            return Optional.of(ErrorResponse.PW_TOO_COMMON);
        }

        return Optional.empty();
    }

    private boolean hasAtLeastOneDigitAndOneNonDigit(String string) {
        char[] charArray = string.toCharArray();
        boolean hasDigit = false;
        boolean hasNonDigit = false;
        for (char c : charArray) {
            if (hasDigit && hasNonDigit) {
                break;
            }
            if (Character.isDigit(c)) {
                hasDigit = true;
                continue;
            }
            hasNonDigit = true;
        }
        return hasDigit && hasNonDigit;
    }
}
