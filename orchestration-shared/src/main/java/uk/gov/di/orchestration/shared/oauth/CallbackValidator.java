package uk.gov.di.orchestration.shared.oauth;

import java.util.Optional;

public interface CallbackValidator {
    Optional<CallbackValidationError> validateError(String error, String description);
}
