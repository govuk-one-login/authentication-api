package uk.gov.di.authentication.frontendapi.entity;

public interface MfaAttemptsStore {

    long getMaxOtpInvalidAttempts();

    boolean shouldBlockWhenMaxAttemptsReached();
}
