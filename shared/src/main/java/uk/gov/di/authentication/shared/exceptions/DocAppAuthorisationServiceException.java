package uk.gov.di.authentication.shared.exceptions;

public class DocAppAuthorisationServiceException extends RuntimeException {
    public DocAppAuthorisationServiceException(Exception e) {
        super(e.getMessage());
    }
}
