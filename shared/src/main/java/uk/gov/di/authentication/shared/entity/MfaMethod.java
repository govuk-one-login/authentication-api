package uk.gov.di.authentication.shared.entity;

public interface MfaMethod {
    String getMfaMethodType();

    boolean isMethodVerified();

    boolean isEnabled();

    String getUpdated();

    MfaMethod withEnabled(boolean enabled);

    MfaMethod withUpdated(String datetime);
}
