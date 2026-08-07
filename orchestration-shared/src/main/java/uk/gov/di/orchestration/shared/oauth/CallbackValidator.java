package uk.gov.di.orchestration.shared.oauth;

public interface CallbackValidator {
    CallbackValidationError handleError(String error, String description);
}
