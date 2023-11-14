package uk.gov.di.orchestration.shared.validation;

import uk.gov.di.orchestration.shared.entity.ErrorResponse;
import uk.gov.di.orchestration.shared.services.CommonPasswordsService;

import java.util.Optional;

public class PasswordValidator {

    private final CommonPasswordsService commonPasswordsService;

    public PasswordValidator(CommonPasswordsService commonPasswordsService) {
        this.commonPasswordsService = commonPasswordsService;
    }

    public Optional<ErrorResponse> validate(String password) {

        if (password == null || password.isBlank()) {
            return Optional.of(ErrorResponse.ERROR_1005);
        }
        if (password.length() < 8 || password.length() > 256) {
            return Optional.of(ErrorResponse.ERROR_1006);
        }
        if (!hasAtLeastOneDigitAndOneNonDigit(password)) {
            return Optional.of(ErrorResponse.ERROR_1007);
        }

        if (commonPasswordsService.isCommonPassword(password)) {
            return Optional.of(ErrorResponse.ERROR_1040);
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
