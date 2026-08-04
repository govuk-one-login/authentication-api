package uk.gov.di.orchestration.shared.oauth;

import java.util.Map;

public interface CallbackValidator {
    CallbackValidationError validateCallback(Map<String, String> queryParams, String sessionId);
}
