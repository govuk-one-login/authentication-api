package uk.gov.di.authentication.shared.entity.mfaMethodManagement;

public interface MfaData {
    MFAMethod toDatabaseRecord(String updated);
}
