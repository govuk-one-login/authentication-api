package uk.gov.di.authentication.shared.entity;

public record SmsMfaData(String endpoint, boolean verified, boolean enabled) implements MfaData {
    @Override
    public MFAMethod toDatabaseRecord(String updated) {
        return new MFAMethod(MFAMethodType.SMS.getValue(), verified, enabled, endpoint, updated);
    }
}
