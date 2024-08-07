package uk.gov.di.authentication.shared.entity;

public interface MfaData {
    MFAMethod toDatabaseRecord(String updated);
}
