package uk.gov.di.authentication.shared.validation;

import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.ValidationHelper;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;

import java.util.Optional;

public class PasswordValidator {

    private CommonPasswordsService commonPasswordsService;

    public PasswordValidator(CommonPasswordsService commonPasswordsService) {
        this.commonPasswordsService = commonPasswordsService;
    }

    public Optional<ErrorResponse> validate(String password) {

        if (password == null || password.isBlank()) {
            return Optional.of(ErrorResponse.ERROR_1005);
        }
        if (password.length() < 8) {
            return Optional.of(ErrorResponse.ERROR_1006);
        }
        if (!ValidationHelper.hasAtLeastOneDigit(password)) {
            return Optional.of(ErrorResponse.ERROR_1007);
        }

        if (commonPasswordsService.isCommonPassword(password)) {
            return Optional.of(ErrorResponse.ERROR_1040);
        }

        return Optional.empty();
    }
}
