package uk.gov.di.authentication.frontendapi.exceptions;

import uk.gov.di.authentication.shared.entity.MFAMethodType;

import static java.lang.String.format;

public class JourneyTypeNotSupportedException extends RuntimeException {

    public JourneyTypeNotSupportedException(MFAMethodType mfaMethodType) {
        super(format("JourneyType not supported for MFAMethodType: %s", mfaMethodType.getValue()));
    }

    public JourneyTypeNotSupportedException(String message) {
        super(message);
    }
}
