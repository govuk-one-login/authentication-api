package uk.gov.di.orchestration.shared.oauth;

public interface CallbackValidationError {
    String code();

    String description();
}
