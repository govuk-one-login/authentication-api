package uk.gov.di.authentication.shared.entity.mfaMethodManagement;

import uk.gov.di.authentication.shared.entity.PriorityIdentifier;

public record AuthAppMfaData(
        String credential,
        boolean verified,
        boolean enabled,
        PriorityIdentifier priority,
        String mfaIdentifier)
        implements MfaData {
    @Override
    public MFAMethod toDatabaseRecord(String updated) {
        return MFAMethod.authAppMfaMethod(
                MFAMethodType.AUTH_APP.getValue(),
                credential,
                verified,
                enabled,
                updated,
                priority,
                mfaIdentifier);
    }
}
