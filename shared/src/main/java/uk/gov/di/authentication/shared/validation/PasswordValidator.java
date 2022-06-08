package uk.gov.di.authentication.shared.validation;


import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;

import java.util.Optional;
import java.util.regex.Pattern;

public class PasswordValidator {

    private static final Pattern PASSWORD_REGEX = Pattern.compile(".*\\d.*");
    private CommonPasswordsService commonPasswordsService;

    public PasswordValidator(CommonPasswordsService commonPasswordsService){
        this.commonPasswordsService = commonPasswordsService;
    }

    public Optional<ErrorResponse> validate(String password) {

        if (password == null || password.isBlank()) {
            return Optional.of(ErrorResponse.ERROR_1005);
        }
        if (password.length() < 8) {
            return Optional.of(ErrorResponse.ERROR_1006);
        }
        if (!PASSWORD_REGEX.matcher(password).matches()) {
            return Optional.of(ErrorResponse.ERROR_1007);
        }

        if (commonPasswordsService.isCommonPassword(password)) {
            return Optional.of(ErrorResponse.ERROR_1040);
        }

        return Optional.empty();
    }


}
