package uk.gov.di.authentication.frontendapi.entity;

public interface MfaRequestStore {

    long getOtpExpiryTime();

    long getMaxOtpRequests();
}
