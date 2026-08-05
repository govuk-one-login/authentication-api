package uk.gov.di.orchestration.shared.oauth;

import java.util.Map;
import java.util.Optional;

public interface CallbackValidator {
    Optional<CallbackValidationError> validateCallback(
            Map<String, String> queryParams, String sessionId);
}
