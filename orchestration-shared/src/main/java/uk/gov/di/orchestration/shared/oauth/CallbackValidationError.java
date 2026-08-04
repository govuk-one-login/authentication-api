package uk.gov.di.orchestration.shared.oauth;

public sealed interface CallbackValidationError permits BaseCallbackValidationError {
    String code();

    String description();
}
