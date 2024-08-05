package uk.gov.di.authentication.shared.entity;

public interface MFAMethod {
    String getMfaMethodType();

    boolean isMethodVerified();

    boolean isEnabled();

    String getUpdated();

    MFAMethod withEnabled(boolean enabled);

    MFAMethod withUpdated(String updated);
}
