package uk.gov.di.authentication.shared.entity;

public record AuthAppMfaData(
        String credential,
        boolean verified,
        boolean enabled,
        PriorityIdentifier priority,
        String mfaIdentifier)
        implements MfaData {
    @Override
    public MFAMethod toDatabaseRecord(String updated) {
        return new MFAMethod(
                MFAMethodType.AUTH_APP.getValue(),
                credential,
                verified,
                enabled,
                updated,
                priority,
                mfaIdentifier);
    }
}
