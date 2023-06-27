package uk.gov.di.authentication.ipv.entity;

import uk.gov.di.authentication.shared.exceptions.NoSessionException;

public class IPVCallbackNoSessionException extends NoSessionException {
    public IPVCallbackNoSessionException(String message) {
        super(message);
    }
}
