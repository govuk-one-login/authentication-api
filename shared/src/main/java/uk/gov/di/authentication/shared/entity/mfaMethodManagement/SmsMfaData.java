package uk.gov.di.authentication.shared.entity.mfaMethodManagement;

import uk.gov.di.authentication.shared.entity.PriorityIdentifier;

public record SmsMfaData(
        String endpoint,
        boolean verified,
        boolean enabled,
        PriorityIdentifier priority,
        String mfaIdentifier)
        implements MfaData {
    @Override
    public MFAMethod toDatabaseRecord(String updated) {
        return new MFAMethod(
                MFAMethodType.SMS.getValue(),
                verified,
                enabled,
                endpoint,
                updated,
                priority,
                mfaIdentifier);
    }
}
