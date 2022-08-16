package uk.gov.di.authentication.shared.validation;

import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

public class SMSCodeValidator extends MfaCodeValidator {

    private final AuthenticationService dynamoService;
    private final UserContext userContext;

    public SMSCodeValidator(
            UserContext userContext,
            CodeStorageService codeStorageService,
            AuthenticationService dynamoService,
            int maxRetries) {
        super(userContext, codeStorageService, maxRetries);
        this.dynamoService = dynamoService;
        this.userContext = userContext;
    }

    @Override
    public Optional<ErrorResponse> validateCode(String code) {

        if (isCodeBlockedForSession()) {
            LOG.info("Code blocked for session");
            return Optional.of(ErrorResponse.ERROR_1027);
        }

        incrementRetryCount();

        if (hasExceededRetryLimit()) {
            LOG.info("Exceeded code retry limit");
            return Optional.of(ErrorResponse.ERROR_1027);
        }

        boolean isValidOtp = isCodeValid(code, NotificationType.VERIFY_PHONE_NUMBER);

        if (!isValidOtp) {
            LOG.info("In");
            return Optional.of(ErrorResponse.ERROR_1035);
        }

        LOG.info("SMS code valid. Resetting code request count");
        resetCodeRequestCount();

        return Optional.empty();
    }
}
